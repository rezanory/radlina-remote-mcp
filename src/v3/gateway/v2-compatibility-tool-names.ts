/** Exact 40 V2 tool names reused by the V3-only local runtime.
 * V3 preserves its own list_devices/get_capabilities and excludes the eight
 * release/WinSW controls whose existing implementation targets the V2 service.
 */
export const V2_COMPATIBILITY_TOOL_NAMES = [
  "who_am_i", "ping", "health", "version", "list_components",
  "list_capabilities", "operator_submit", "operator_status", "operator_recent",
  "operator_resume", "operator_cancel", "list_directory", "read_file",
  "read_multiple_files", "get_file_info", "create_directory", "write_file",
  "edit_block", "copy", "move", "trash", "start_search", "search_status",
  "search_results", "cancel_search", "list_processes", "start_process",
  "read_process_output", "interact_with_process", "terminate_process",
  "get_effective_config", "validate_config", "simulate_policy",
  "recent_tool_calls", "auth_health", "recent_oauth_events",
  "active_sessions", "resource_stats", "readiness", "error_details",
] as const;
