#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Procmon PMC Configuration Generator

A tool to generate Process Monitor (Procmon) PMC configuration files
based on user-defined filter conditions.

Usage:
    python pmc_generator.py [options]

Options:
    -i, --interactive    Interactive mode (guided prompts)
    -j, --json FILE      Load filters from JSON file
    -o, --output FILE    Output PMC file path (default: output.pmc)
    -t, --template       Generate a sample JSON template
    -h, --help           Show this help message

example: python pmc_generator.py -j malware_mon.json -o malware_mon.pmc -s
"""

import argparse
import json
import sys
import os
from collections import OrderedDict

# Add local procmon-parser project to path
_LOCAL_PROCMON_PARSER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'projects', 'procmon-parser')
if os.path.exists(_LOCAL_PROCMON_PARSER):
    sys.path.insert(0, _LOCAL_PROCMON_PARSER)

# Import procmon_parser components
try:
    from procmon_parser import (
        dump_configuration, Rule, Column, RuleAction, RuleRelation, Font
    )
except ImportError as e:
    print(f"Error: procmon_parser is not available: {e}")
    print(f"Looking for: {_LOCAL_PROCMON_PARSER}")
    sys.exit(1)


# Column display names mapping (user-friendly names)
COLUMN_DISPLAY_NAMES = {
    'date_and_time': Column.DATE_AND_TIME,
    'process_name': Column.PROCESS_NAME,
    'pid': Column.PID,
    'operation': Column.OPERATION,
    'result': Column.RESULT,
    'detail': Column.DETAIL,
    'sequence': Column.SEQUENCE,
    'company': Column.COMPANY,
    'description': Column.DESCRIPTION,
    'command_line': Column.COMMAND_LINE,
    'user': Column.USER,
    'image_path': Column.IMAGE_PATH,
    'session': Column.SESSION,
    'path': Column.PATH,
    'tid': Column.TID,
    'relative_time': Column.RELATIVE_TIME,
    'duration': Column.DURATION,
    'time_of_day': Column.TIME_OF_DAY,
    'version': Column.VERSION,
    'event_class': Column.EVENT_CLASS,
    'authentication_id': Column.AUTHENTICATION_ID,
    'virtualized': Column.VIRTUALIZED,
    'integrity': Column.INTEGRITY,
    'category': Column.CATEGORY,
    'parent_pid': Column.PARENT_PID,
    'architecture': Column.ARCHITECTURE,
    'completion_time': Column.COMPLETION_TIME,
}

# Relation display names mapping
RELATION_DISPLAY_NAMES = {
    'is': RuleRelation.IS,
    'is_not': RuleRelation.IS_NOT,
    'less_than': RuleRelation.LESS_THAN,
    'more_than': RuleRelation.MORE_THAN,
    'begins_with': RuleRelation.BEGINS_WITH,
    'ends_with': RuleRelation.ENDS_WITH,
    'contains': RuleRelation.CONTAINS,
    'excludes': RuleRelation.EXCLUDES,
}

# Action display names mapping
ACTION_DISPLAY_NAMES = {
    'include': RuleAction.INCLUDE,
    'exclude': RuleAction.EXCLUDE,
}


def get_default_configuration():
    """Create a default Procmon configuration with common settings."""
    config = OrderedDict()

    # Default column widths
    config['Columns'] = [260, 100, 60, 100, 80, 200, 60, 80, 80, 150, 100, 200, 60, 300, 60, 80, 80, 80, 80, 80, 80, 60, 60, 60, 60, 60, 80]
    config['ColumnCount'] = 10

    # Default column order
    config['ColumnMap'] = [
        Column.TIME_OF_DAY,
        Column.PROCESS_NAME,
        Column.PID,
        Column.OPERATION,
        Column.PATH,
        Column.RESULT,
        Column.DETAIL,
        Column.IMAGE_PATH,
        Column.COMPANY,
        Column.DESCRIPTION,
    ]

    # Paths
    config['DbgHelpPath'] = "C:\\Program Files (x86)\\Windows Kits\\10\\Debuggers\\x64\\dbghelp.dll"
    config['SourcePath'] = ""
    config['SymbolPath'] = "SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols"

    # Display settings
    config['HighlightFG'] = 0x00000000  # Black
    config['HighlightBG'] = 0x0000FFFF  # Yellow
    # Font height: use positive value for default
    config['LogFont'] = Font(height=11, width=0, weight=400, face_name="Segoe UI")
    config['BoookmarkFont'] = Font(height=11, width=0, weight=400, face_name="Segoe UI")

    # Behavior settings
    config['AdvancedMode'] = 0
    config['Autoscroll'] = 1
    config['HistoryDepth'] = 5  # 5 million events
    config['Profiling'] = 0
    config['DestructiveFilter'] = 1  # Drop filtered events
    config['AlwaysOnTop'] = 0
    config['ResolveAddresses'] = 1

    # Default filter rules (exclude common noise)
    config['FilterRules'] = [
        Rule(Column.PROCESS_NAME, RuleRelation.IS, "System", RuleAction.EXCLUDE),
        Rule(Column.PROCESS_NAME, RuleRelation.IS, "Procmon64.exe", RuleAction.EXCLUDE),
        Rule(Column.PROCESS_NAME, RuleRelation.IS, "Procmon.exe", RuleAction.EXCLUDE),
        Rule(Column.PROCESS_NAME, RuleRelation.IS, "Procexp64.exe", RuleAction.EXCLUDE),
        Rule(Column.PROCESS_NAME, RuleRelation.IS, "Procexp.exe", RuleAction.EXCLUDE),
        Rule(Column.OPERATION, RuleRelation.BEGINS_WITH, "IRP_MJ_", RuleAction.EXCLUDE),
        Rule(Column.OPERATION, RuleRelation.BEGINS_WITH, "FASTIO_", RuleAction.EXCLUDE),
        Rule(Column.RESULT, RuleRelation.BEGINS_WITH, "FAST IO", RuleAction.EXCLUDE),
        Rule(Column.EVENT_CLASS, RuleRelation.IS, "Profiling", RuleAction.EXCLUDE),
    ]

    # Highlight rules (empty by default)
    config['HighlightRules'] = []

    return config


def parse_column_name(name):
    """Parse column name from string (case-insensitive, accepts multiple formats)."""
    name_lower = name.lower().replace(' ', '_').replace('-', '_')

    if name_lower in COLUMN_DISPLAY_NAMES:
        return COLUMN_DISPLAY_NAMES[name_lower]

    # Try to match by removing underscores
    name_no_sep = name_lower.replace('_', '')
    for key, col in COLUMN_DISPLAY_NAMES.items():
        if key.replace('_', '') == name_no_sep:
            return col

    # Try enum name directly
    try:
        return Column[name.upper()]
    except KeyError:
        pass

    raise ValueError(f"Unknown column name: {name}. Valid columns: {list(COLUMN_DISPLAY_NAMES.keys())}")


def parse_relation_name(name):
    """Parse relation name from string."""
    name_lower = name.lower().replace(' ', '_').replace('-', '_')

    if name_lower in RELATION_DISPLAY_NAMES:
        return RELATION_DISPLAY_NAMES[name_lower]

    try:
        return RuleRelation[name.upper()]
    except KeyError:
        pass

    raise ValueError(f"Unknown relation: {name}. Valid relations: {list(RELATION_DISPLAY_NAMES.keys())}")


def parse_action_name(name):
    """Parse action name from string."""
    name_lower = name.lower().replace(' ', '_').replace('-', '_')

    if name_lower in ACTION_DISPLAY_NAMES:
        return ACTION_DISPLAY_NAMES[name_lower]

    try:
        return RuleAction[name.upper()]
    except KeyError:
        pass

    raise ValueError(f"Unknown action: {name}. Valid actions: {list(ACTION_DISPLAY_NAMES.keys())}")


def create_rule_from_dict(rule_dict):
    """Create a Rule object from a dictionary."""
    column = parse_column_name(rule_dict.get('column', 'process_name'))
    relation = parse_relation_name(rule_dict.get('relation', 'is'))
    value = rule_dict.get('value', '')
    action = parse_action_name(rule_dict.get('action', 'exclude'))

    return Rule(column, relation, value, action)


def load_filters_from_json(json_file):
    """Load filter configuration from a JSON file."""
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    config = get_default_configuration()

    # Parse filter rules
    if 'filter_rules' in data:
        filter_rules = []
        for rule_dict in data['filter_rules']:
            filter_rules.append(create_rule_from_dict(rule_dict))
        config['FilterRules'] = filter_rules

    # Parse highlight rules
    if 'highlight_rules' in data:
        highlight_rules = []
        for rule_dict in data['highlight_rules']:
            highlight_rules.append(create_rule_from_dict(rule_dict))
        config['HighlightRules'] = highlight_rules

    # Override other settings
    if 'destructive_filter' in data:
        config['DestructiveFilter'] = 1 if data['destructive_filter'] else 0

    if 'history_depth' in data:
        config['HistoryDepth'] = data['history_depth']

    if 'logfile' in data:
        config['Logfile'] = data['logfile']

    if 'autoscroll' in data:
        config['Autoscroll'] = 1 if data['autoscroll'] else 0

    if 'columns' in data:
        # Override column settings
        if 'map' in data['columns']:
            column_map = []
            for col_name in data['columns']['map']:
                column_map.append(parse_column_name(col_name))
            config['ColumnMap'] = column_map
            config['ColumnCount'] = len(column_map)

    return config


def generate_json_template(output_file):
    """Generate a sample JSON template file."""
    template = {
        "description": "Procmon PMC Configuration Template",
        "destructive_filter": True,
        "history_depth": 5,
        "autoscroll": True,
        "logfile": "",
        "columns": {
            "map": [
                "time_of_day",
                "process_name",
                "pid",
                "operation",
                "path",
                "result"
            ]
        },
        "filter_rules": [
            {
                "column": "process_name",
                "relation": "is",
                "value": "System",
                "action": "exclude",
                "comment": "Exclude System process"
            },
            {
                "column": "process_name",
                "relation": "contains",
                "value": "chrome.exe",
                "action": "include",
                "comment": "Include Chrome browser events"
            },
            {
                "column": "path",
                "relation": "contains",
                "value": "C:\\Users\\",
                "action": "include",
                "comment": "Include user directory access"
            },
            {
                "column": "operation",
                "relation": "is",
                "value": "Process Create",
                "action": "include",
                "comment": "Include process creation events"
            },
            {
                "column": "result",
                "relation": "is_not",
                "value": "SUCCESS",
                "action": "include",
                "comment": "Include failed operations"
            }
        ],
        "highlight_rules": [
            {
                "column": "result",
                "relation": "contains",
                "value": "DENIED",
                "action": "include",
                "comment": "Highlight access denied events"
            },
            {
                "column": "operation",
                "relation": "is",
                "value": "Process Create",
                "action": "include",
                "comment": "Highlight process creation"
            }
        ],
        "_help": {
            "columns": list(COLUMN_DISPLAY_NAMES.keys()),
            "relations": list(RELATION_DISPLAY_NAMES.keys()),
            "actions": list(ACTION_DISPLAY_NAMES.keys())
        }
    }

    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(template, f, indent=2, ensure_ascii=False)

    print(f"JSON template saved to: {output_file}")


def interactive_mode():
    """Interactive mode for creating filters."""
    print("\n" + "="*60)
    print("Procmon PMC Configuration Generator - Interactive Mode")
    print("="*60)

    config = get_default_configuration()
    filter_rules = []

    print("\nAvailable columns:")
    for i, col in enumerate(COLUMN_DISPLAY_NAMES.keys(), 1):
        print(f"  {i:2d}. {col}")

    print("\nAvailable relations:")
    for i, rel in enumerate(RELATION_DISPLAY_NAMES.keys(), 1):
        print(f"  {i:2d}. {rel}")

    print("\nAvailable actions:")
    for i, act in enumerate(ACTION_DISPLAY_NAMES.keys(), 1):
        print(f"  {i:2d}. {act}")

    print("\n" + "-"*60)
    print("Add Filter Rules (press Enter with empty column to finish)")
    print("-"*60)

    while True:
        print("\nNew Rule:")

        # Get column
        column_input = input("Column (or empty to finish): ").strip()
        if not column_input:
            break

        try:
            column = parse_column_name(column_input)
        except ValueError as e:
            print(f"Error: {e}")
            continue

        # Get relation
        relation_input = input("Relation: ").strip()
        try:
            relation = parse_relation_name(relation_input)
        except ValueError as e:
            print(f"Error: {e}")
            continue

        # Get value
        value = input("Value: ").strip()

        # Get action
        action_input = input("Action (include/exclude): ").strip()
        try:
            action = parse_action_name(action_input)
        except ValueError as e:
            print(f"Error: {e}")
            continue

        # Create rule
        rule = Rule(column, relation, value, action)
        filter_rules.append(rule)
        print(f"Added rule: {rule}")

    # Ask for destructive filter
    destructive = input("\nEnable destructive filter (drop filtered events)? [y/N]: ").strip().lower()
    config['DestructiveFilter'] = 1 if destructive.startswith('y') else 0

    # Ask for history depth
    depth_input = input("History depth (million events, default 5): ").strip()
    if depth_input:
        try:
            config['HistoryDepth'] = int(depth_input)
        except ValueError:
            print("Invalid number, using default 5")

    # Set filter rules
    if filter_rules:
        config['FilterRules'] = filter_rules + config['FilterRules']

    return config


def save_pmc_file(config, output_file):
    """Save configuration to PMC file."""
    with open(output_file, 'wb') as f:
        dump_configuration(config, f)
    print(f"\nPMC configuration saved to: {output_file}")
    print(f"Total filter rules: {len(config['FilterRules'])}")
    print(f"Destructive filter: {config['DestructiveFilter']}")


def print_filter_summary(config):
    """Print a summary of the filter rules."""
    print("\n" + "="*60)
    print("Filter Rules Summary")
    print("="*60)

    for i, rule in enumerate(config['FilterRules'], 1):
        print(f"  {i:2d}. {rule}")

    print("\nSettings:")
    print(f"  - Destructive Filter: {config['DestructiveFilter']}")
    print(f"  - History Depth: {config['HistoryDepth']} million events")
    print(f"  - Auto Scroll: {config['Autoscroll']}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate Procmon PMC configuration files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument('-i', '--interactive', action='store_true',
                        help='Interactive mode (guided prompts)')
    parser.add_argument('-j', '--json', metavar='FILE',
                        help='Load filters from JSON file')
    parser.add_argument('-o', '--output', metavar='FILE', default='output.pmc',
                        help='Output PMC file path (default: output.pmc)')
    parser.add_argument('-t', '--template', action='store_true',
                        help='Generate a sample JSON template file')
    parser.add_argument('-s', '--summary', action='store_true',
                        help='Show summary after generation')

    args = parser.parse_args()

    # Generate template
    if args.template:
        template_file = 'pmc_template.json'
        generate_json_template(template_file)
        return

    # Determine mode
    if args.interactive:
        config = interactive_mode()
    elif args.json:
        if not os.path.exists(args.json):
            print(f"Error: JSON file not found: {args.json}")
            sys.exit(1)
        config = load_filters_from_json(args.json)
        print(f"Loaded configuration from: {args.json}")
    else:
        # Default: create empty configuration
        print("No input specified. Use -i for interactive mode or -j to load JSON file.")
        print("Generating default PMC file with standard filters...")
        config = get_default_configuration()

    # Show summary if requested
    if args.summary:
        print_filter_summary(config)

    # Save PMC file
    save_pmc_file(config, args.output)


if __name__ == '__main__':
    main()