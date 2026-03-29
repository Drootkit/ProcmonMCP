"""
PMC Configuration Generator Module

Generates Procmon PMC configuration files based on user-defined filter conditions.
Ported from pmc_generator.py for MCP integration.
"""

import json
import os
import logging
from collections import OrderedDict
from typing import Dict, Any, List, Optional
from datetime import datetime

# Try to import procmon_parser
try:
    # Try importing from local procmon-parser project
    _LOCAL_PROCMON_PARSER = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        'procmon-parser'
    )
    if os.path.exists(_LOCAL_PROCMON_PARSER):
        import sys
        if _LOCAL_PROCMON_PARSER not in sys.path:
            sys.path.insert(0, _LOCAL_PROCMON_PARSER)

    from procmon_parser import (
        dump_configuration, Rule, Column, RuleAction, RuleRelation, Font
    )
    PROCMON_PARSER_AVAILABLE = True
except ImportError as e:
    PROCMON_PARSER_AVAILABLE = False
    _IMPORT_ERROR = str(e)

logger = logging.getLogger(__name__)


# Column display names mapping (user-friendly names)
COLUMN_DISPLAY_NAMES = {
    'date_and_time': Column.DATE_AND_TIME if PROCMON_PARSER_AVAILABLE else None,
    'process_name': Column.PROCESS_NAME if PROCMON_PARSER_AVAILABLE else None,
    'pid': Column.PID if PROCMON_PARSER_AVAILABLE else None,
    'operation': Column.OPERATION if PROCMON_PARSER_AVAILABLE else None,
    'result': Column.RESULT if PROCMON_PARSER_AVAILABLE else None,
    'detail': Column.DETAIL if PROCMON_PARSER_AVAILABLE else None,
    'sequence': Column.SEQUENCE if PROCMON_PARSER_AVAILABLE else None,
    'company': Column.COMPANY if PROCMON_PARSER_AVAILABLE else None,
    'description': Column.DESCRIPTION if PROCMON_PARSER_AVAILABLE else None,
    'command_line': Column.COMMAND_LINE if PROCMON_PARSER_AVAILABLE else None,
    'user': Column.USER if PROCMON_PARSER_AVAILABLE else None,
    'image_path': Column.IMAGE_PATH if PROCMON_PARSER_AVAILABLE else None,
    'session': Column.SESSION if PROCMON_PARSER_AVAILABLE else None,
    'path': Column.PATH if PROCMON_PARSER_AVAILABLE else None,
    'tid': Column.TID if PROCMON_PARSER_AVAILABLE else None,
    'relative_time': Column.RELATIVE_TIME if PROCMON_PARSER_AVAILABLE else None,
    'duration': Column.DURATION if PROCMON_PARSER_AVAILABLE else None,
    'time_of_day': Column.TIME_OF_DAY if PROCMON_PARSER_AVAILABLE else None,
    'version': Column.VERSION if PROCMON_PARSER_AVAILABLE else None,
    'event_class': Column.EVENT_CLASS if PROCMON_PARSER_AVAILABLE else None,
    'authentication_id': Column.AUTHENTICATION_ID if PROCMON_PARSER_AVAILABLE else None,
    'virtualized': Column.VIRTUALIZED if PROCMON_PARSER_AVAILABLE else None,
    'integrity': Column.INTEGRITY if PROCMON_PARSER_AVAILABLE else None,
    'category': Column.CATEGORY if PROCMON_PARSER_AVAILABLE else None,
    'parent_pid': Column.PARENT_PID if PROCMON_PARSER_AVAILABLE else None,
    'architecture': Column.ARCHITECTURE if PROCMON_PARSER_AVAILABLE else None,
    'completion_time': Column.COMPLETION_TIME if PROCMON_PARSER_AVAILABLE else None,
}

# Relation display names mapping
RELATION_DISPLAY_NAMES = {
    'is': RuleRelation.IS if PROCMON_PARSER_AVAILABLE else None,
    'is_not': RuleRelation.IS_NOT if PROCMON_PARSER_AVAILABLE else None,
    'less_than': RuleRelation.LESS_THAN if PROCMON_PARSER_AVAILABLE else None,
    'more_than': RuleRelation.MORE_THAN if PROCMON_PARSER_AVAILABLE else None,
    'begins_with': RuleRelation.BEGINS_WITH if PROCMON_PARSER_AVAILABLE else None,
    'ends_with': RuleRelation.ENDS_WITH if PROCMON_PARSER_AVAILABLE else None,
    'contains': RuleRelation.CONTAINS if PROCMON_PARSER_AVAILABLE else None,
    'excludes': RuleRelation.EXCLUDES if PROCMON_PARSER_AVAILABLE else None,
}

# Action display names mapping
ACTION_DISPLAY_NAMES = {
    'include': RuleAction.INCLUDE if PROCMON_PARSER_AVAILABLE else None,
    'exclude': RuleAction.EXCLUDE if PROCMON_PARSER_AVAILABLE else None,
}


# Default configuration template (based on malware_mon.json)
DEFAULT_CONFIG_TEMPLATE = {
    "description": "Procmon Capture Configuration",
    "destructive_filter": True,
    "history_depth": 10,
    "autoscroll": True,
    "logfile": "",
    "columns": {
        "map": [
            "time_of_day",
            "process_name",
            "pid",
            "operation",
            "path",
            "result",
            "detail",
            "image_path"
        ]
    },
    "filter_rules": [
        {
            "column": "process_name",
            "relation": "contains",
            "value": "loader",
            "action": "include",
            "comment": "Include all events from target process"
        },
        {
            "column": "process_name",
            "relation": "is",
            "value": "System",
            "action": "exclude",
            "comment": "Exclude System process noise"
        },
        {
            "column": "process_name",
            "relation": "contains",
            "value": "Procmon",
            "action": "exclude",
            "comment": "Exclude Procmon itself"
        },
        {
            "column": "operation",
            "relation": "begins_with",
            "value": "IRP_MJ_",
            "action": "exclude",
            "comment": "Exclude low-level IRP operations"
        },
        {
            "column": "operation",
            "relation": "begins_with",
            "value": "FASTIO_",
            "action": "exclude",
            "comment": "Exclude FASTIO operations"
        },
        {
            "column": "result",
            "relation": "begins_with",
            "value": "FAST IO",
            "action": "exclude",
            "comment": "Exclude FAST IO results"
        },
        {
            "column": "event_class",
            "relation": "is",
            "value": "Profiling",
            "action": "exclude",
            "comment": "Exclude profiling events"
        }
    ],
    "highlight_rules": [
        {
            "column": "operation",
            "relation": "is",
            "value": "Process Create",
            "action": "include",
            "comment": "Highlight process creation"
        }
    ]
}


def check_procmon_parser_available() -> tuple:
    """Check if procmon_parser is available. Returns (available, error_message)."""
    return PROCMON_PARSER_AVAILABLE, None if PROCMON_PARSER_AVAILABLE else _IMPORT_ERROR


def parse_column_name(name: str) -> 'Column':
    """Parse column name from string (case-insensitive, accepts multiple formats)."""
    if not PROCMON_PARSER_AVAILABLE:
        raise RuntimeError("procmon_parser is not available")

    name_lower = name.lower().replace(' ', '_').replace('-', '_')

    if name_lower in COLUMN_DISPLAY_NAMES and COLUMN_DISPLAY_NAMES[name_lower] is not None:
        return COLUMN_DISPLAY_NAMES[name_lower]

    # Try to match by removing underscores
    name_no_sep = name_lower.replace('_', '')
    for key, col in COLUMN_DISPLAY_NAMES.items():
        if col is not None and key.replace('_', '') == name_no_sep:
            return col

    # Try enum name directly
    try:
        return Column[name.upper()]
    except KeyError:
        pass

    raise ValueError(f"Unknown column name: {name}. Valid columns: {list(COLUMN_DISPLAY_NAMES.keys())}")


def parse_relation_name(name: str) -> 'RuleRelation':
    """Parse relation name from string."""
    if not PROCMON_PARSER_AVAILABLE:
        raise RuntimeError("procmon_parser is not available")

    name_lower = name.lower().replace(' ', '_').replace('-', '_')

    if name_lower in RELATION_DISPLAY_NAMES and RELATION_DISPLAY_NAMES[name_lower] is not None:
        return RELATION_DISPLAY_NAMES[name_lower]

    try:
        return RuleRelation[name.upper()]
    except KeyError:
        pass

    raise ValueError(f"Unknown relation: {name}. Valid relations: {list(RELATION_DISPLAY_NAMES.keys())}")


def parse_action_name(name: str) -> 'RuleAction':
    """Parse action name from string."""
    if not PROCMON_PARSER_AVAILABLE:
        raise RuntimeError("procmon_parser is not available")

    name_lower = name.lower().replace(' ', '_').replace('-', '_')

    if name_lower in ACTION_DISPLAY_NAMES and ACTION_DISPLAY_NAMES[name_lower] is not None:
        return ACTION_DISPLAY_NAMES[name_lower]

    try:
        return RuleAction[name.upper()]
    except KeyError:
        pass

    raise ValueError(f"Unknown action: {name}. Valid actions: {list(ACTION_DISPLAY_NAMES.keys())}")


def create_rule_from_dict(rule_dict: Dict[str, Any]) -> 'Rule':
    """Create a Rule object from a dictionary."""
    column = parse_column_name(rule_dict.get('column', 'process_name'))
    relation = parse_relation_name(rule_dict.get('relation', 'is'))
    value = rule_dict.get('value', '')
    action = parse_action_name(rule_dict.get('action', 'exclude'))

    return Rule(column, relation, value, action)


def get_default_configuration() -> OrderedDict:
    """Create a default Procmon configuration with common settings."""
    if not PROCMON_PARSER_AVAILABLE:
        raise RuntimeError("procmon_parser is not available")

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
    config['LogFont'] = Font(height=11, width=0, weight=400, face_name="Segoe UI")
    config['BoookmarkFont'] = Font(height=11, width=0, weight=400, face_name="Segoe UI")

    # Behavior settings
    config['AdvancedMode'] = 0
    config['Autoscroll'] = 1
    config['HistoryDepth'] = 5
    config['Profiling'] = 0
    config['DestructiveFilter'] = 1
    config['AlwaysOnTop'] = 0
    config['ResolveAddresses'] = 1

    # Default filter rules
    config['FilterRules'] = [
        Rule(Column.PROCESS_NAME, RuleRelation.IS, "System", RuleAction.EXCLUDE),
        Rule(Column.PROCESS_NAME, RuleRelation.IS, "Procmon64.exe", RuleAction.EXCLUDE),
        Rule(Column.PROCESS_NAME, RuleRelation.IS, "Procmon.exe", RuleAction.EXCLUDE),
        Rule(Column.OPERATION, RuleRelation.BEGINS_WITH, "IRP_MJ_", RuleAction.EXCLUDE),
        Rule(Column.OPERATION, RuleRelation.BEGINS_WITH, "FASTIO_", RuleAction.EXCLUDE),
        Rule(Column.RESULT, RuleRelation.BEGINS_WITH, "FAST IO", RuleAction.EXCLUDE),
        Rule(Column.EVENT_CLASS, RuleRelation.IS, "Profiling", RuleAction.EXCLUDE),
    ]

    # Highlight rules (empty by default)
    config['HighlightRules'] = []

    return config


def generate_capture_config(
    process_filter: str = "loader",
    relation: str = "contains",
    action: str = "include",
    destructive_filter: bool = True,
    history_depth: int = 10,
    additional_exclude_rules: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Generate a capture configuration JSON based on user parameters.

    Args:
        process_filter: Process name filter value (default: "loader")
        relation: Relation type (default: "contains")
        action: Filter action (default: "include")
        destructive_filter: Whether to drop filtered events
        history_depth: History depth in millions of events
        additional_exclude_rules: Additional exclude rules to append

    Returns:
        Dictionary containing the configuration
    """
    config = DEFAULT_CONFIG_TEMPLATE.copy()

    # Update the first filter rule with user-specified process filter
    config["filter_rules"] = config["filter_rules"].copy()
    config["filter_rules"][0] = {
        "column": "process_name",
        "relation": relation,
        "value": process_filter,
        "action": action,
        "comment": f"Include all events from processes matching '{process_filter}'"
    }

    # Update settings
    config["destructive_filter"] = destructive_filter
    config["history_depth"] = history_depth

    # Add additional exclude rules if provided
    if additional_exclude_rules:
        for rule in additional_exclude_rules:
            config["filter_rules"].append(rule)

    return config


def config_dict_to_pmc(config_dict: Dict[str, Any]) -> bytes:
    """
    Convert a configuration dictionary to PMC binary format.

    Args:
        config_dict: Configuration dictionary

    Returns:
        PMC file content as bytes
    """
    if not PROCMON_PARSER_AVAILABLE:
        raise RuntimeError("procmon_parser is not available")

    # Build the configuration
    config = get_default_configuration()

    # Parse filter rules
    if 'filter_rules' in config_dict:
        filter_rules = []
        for rule_dict in config_dict['filter_rules']:
            try:
                filter_rules.append(create_rule_from_dict(rule_dict))
            except Exception as e:
                logger.warning(f"Failed to parse rule {rule_dict}: {e}")
        config['FilterRules'] = filter_rules

    # Parse highlight rules
    if 'highlight_rules' in config_dict:
        highlight_rules = []
        for rule_dict in config_dict['highlight_rules']:
            try:
                highlight_rules.append(create_rule_from_dict(rule_dict))
            except Exception as e:
                logger.warning(f"Failed to parse highlight rule {rule_dict}: {e}")
        config['HighlightRules'] = highlight_rules

    # Override other settings
    if 'destructive_filter' in config_dict:
        config['DestructiveFilter'] = 1 if config_dict['destructive_filter'] else 0

    if 'history_depth' in config_dict:
        config['HistoryDepth'] = config_dict['history_depth']

    if 'autoscroll' in config_dict:
        config['Autoscroll'] = 1 if config_dict['autoscroll'] else 0

    if 'columns' in config_dict and 'map' in config_dict['columns']:
        column_map = []
        for col_name in config_dict['columns']['map']:
            try:
                column_map.append(parse_column_name(col_name))
            except Exception as e:
                logger.warning(f"Failed to parse column {col_name}: {e}")
        if column_map:
            config['ColumnMap'] = column_map
            config['ColumnCount'] = len(column_map)

    # Serialize to PMC binary format
    from io import BytesIO
    output = BytesIO()
    dump_configuration(config, output)
    return output.getvalue()


def save_pmc_file(config_dict: Dict[str, Any], output_path: str) -> Dict[str, Any]:
    """
    Save configuration dictionary to a PMC file.

    Args:
        config_dict: Configuration dictionary
        output_path: Output file path

    Returns:
        Result dictionary with success status and details
    """
    if not PROCMON_PARSER_AVAILABLE:
        return {
            "success": False,
            "error": f"procmon_parser is not available: {_IMPORT_ERROR}"
        }

    try:
        pmc_bytes = config_dict_to_pmc(config_dict)

        with open(output_path, 'wb') as f:
            f.write(pmc_bytes)

        return {
            "success": True,
            "output_path": os.path.abspath(output_path),
            "file_size": len(pmc_bytes),
            "filter_rules_count": len(config_dict.get('filter_rules', [])),
            "message": f"PMC file saved to {output_path}"
        }

    except Exception as e:
        logger.exception("Failed to save PMC file")
        return {
            "success": False,
            "error": str(e)
        }


def generate_default_output_filename(process_filter: str, runtime_seconds: int) -> str:
    """
    Generate a default output filename based on capture parameters.

    Format: <timestamp>_<filter>.PML

    Args:
        process_filter: Process name filter
        runtime_seconds: Capture duration

    Returns:
        Generated filename
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Sanitize process filter for filename
    safe_filter = "".join(c if c.isalnum() or c in "_-" else "_" for c in process_filter)
    return f"{timestamp}_{safe_filter}.PML"