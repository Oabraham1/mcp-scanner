//! Detects overly broad permission scopes in tools.
//!
//! This detector focuses on REAL threats with minimal false positives:
//! - Actual code execution (shell, eval, exec in descriptions)
//! - Credential exposure (tools that return/handle secrets)
//! - Root filesystem access (server configured with / or ~)

use crate::discovery::ServerConfig;
use crate::scanner::report::{ResourceInfo, Severity, Threat, ThreatCategory, ToolInfo};
use crate::scanner::threats::ThreatDetector;
use regex::Regex;
use std::sync::LazyLock;

/// Patterns that indicate ACTUAL code execution capability.
/// Must match in the tool DESCRIPTION, not just the name.
static CODE_EXEC_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(executes?|runs?|spawns?)\s+(a\s+)?(shell|command|script|code|program|process)\b",
    )
    .unwrap()
});

/// Patterns that indicate the tool handles credentials.
/// Must match in description showing the tool RETURNS or EXPOSES secrets.
static CREDENTIAL_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(returns?|gets?|retrieves?|exposes?|outputs?)\s+.{0,20}(password|secret|token|api.?key|credential|private.?key)\b").unwrap()
});

/// Patterns that indicate raw SQL execution (not just database access).
static RAW_SQL_PATTERNS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(executes?|runs?)\s+(raw\s+|arbitrary\s+)?(sql|query|queries)\b").unwrap()
});

pub struct PermissionScopeDetector;

impl PermissionScopeDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_server_args(&self, server: &ServerConfig) -> Vec<Threat> {
        let mut threats = Vec::new();

        // Check if server has root filesystem access
        let args_str = server.args.join(" ");
        let has_root_access = args_str.contains(" / ")
            || args_str.ends_with(" /")
            || args_str.contains(" /\"")
            || args_str.contains(" /'")
            || server
                .args
                .iter()
                .any(|a| a == "/" || a == "~" || a == "/home" || a == "/Users");

        if has_root_access {
            threats.push(
                Threat::new(
                    "PERM-ROOT",
                    Severity::High,
                    ThreatCategory::PermissionScope,
                    "Server has root filesystem access",
                )
                .with_message(format!(
                    "Server '{}' is configured with access to root or home directories",
                    server.name
                ))
                .with_evidence(format!("Args: {}", args_str))
                .with_remediation(
                    "Restrict filesystem access to specific directories needed for the task",
                ),
            );
        }

        threats
    }

    fn check_tool(&self, tool: &ToolInfo) -> Vec<Threat> {
        let mut threats = Vec::new();
        let description = tool.description.as_deref().unwrap_or("");

        // Only check DESCRIPTIONS for dangerous capabilities, not names

        // Code execution - must explicitly say it runs commands
        if CODE_EXEC_PATTERNS.is_match(description) {
            threats.push(
                Threat::new(
                    format!("PERM-EXEC-{}", tool.name),
                    Severity::Critical,
                    ThreatCategory::PermissionScope,
                    "Code execution capability",
                )
                .with_message(format!(
                    "Tool '{}' can execute shell commands or code",
                    tool.name
                ))
                .with_evidence(description.chars().take(200).collect::<String>())
                .with_remediation(
                    "Ensure commands are validated against an allowlist. Consider sandboxing.",
                )
                .with_tool(&tool.name),
            );
        }

        // Credential exposure - must say it returns/gets secrets
        if CREDENTIAL_PATTERNS.is_match(description) {
            threats.push(
                Threat::new(
                    format!("PERM-CRED-{}", tool.name),
                    Severity::High,
                    ThreatCategory::PermissionScope,
                    "Exposes credentials",
                )
                .with_message(format!(
                    "Tool '{}' may expose sensitive credentials",
                    tool.name
                ))
                .with_evidence(description.chars().take(200).collect::<String>())
                .with_remediation(
                    "Credentials should not be returned to the AI. Use secure references instead.",
                )
                .with_tool(&tool.name),
            );
        }

        // Raw SQL execution
        if RAW_SQL_PATTERNS.is_match(description) {
            threats.push(
                Threat::new(
                    format!("PERM-SQL-{}", tool.name),
                    Severity::High,
                    ThreatCategory::PermissionScope,
                    "Raw SQL execution",
                )
                .with_message(format!(
                    "Tool '{}' can execute arbitrary SQL queries",
                    tool.name
                ))
                .with_evidence(description.chars().take(200).collect::<String>())
                .with_remediation(
                    "Use parameterized queries and restrict to read-only operations where possible.",
                )
                .with_tool(&tool.name),
            );
        }

        threats
    }
}

impl Default for PermissionScopeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatDetector for PermissionScopeDetector {
    fn detect(
        &self,
        server: &ServerConfig,
        tools: &[ToolInfo],
        _resources: &[ResourceInfo],
    ) -> Vec<Threat> {
        let mut threats = self.check_server_args(server);
        threats.extend(tools.iter().flat_map(|tool| self.check_tool(tool)));
        threats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tool(name: &str, description: &str) -> ToolInfo {
        ToolInfo {
            name: name.to_string(),
            description: Some(description.to_string()),
            input_schema: serde_json::json!({}),
        }
    }

    #[test]
    fn detects_code_execution() {
        let detector = PermissionScopeDetector::new();
        let tools = vec![make_tool(
            "run_command",
            "Executes a shell command on the system",
        )];

        let threats = detector.detect(&ServerConfig::new("test", "cmd"), &tools, &[]);
        assert!(!threats.is_empty());
        assert!(threats.iter().any(|t| t.title.contains("Code execution")));
    }

    #[test]
    fn no_false_positive_for_read_file() {
        let detector = PermissionScopeDetector::new();
        let tools = vec![make_tool(
            "read_file",
            "Read the contents of a file from the filesystem",
        )];

        let threats = detector.detect(&ServerConfig::new("test", "cmd"), &tools, &[]);
        // Should NOT flag read_file as code execution
        assert!(!threats.iter().any(|t| t.title.contains("Code execution")));
    }

    #[test]
    fn detects_credential_handling() {
        let detector = PermissionScopeDetector::new();
        let tools = vec![make_tool(
            "get_api_key",
            "Retrieves the API key from the environment and returns it",
        )];

        let threats = detector.detect(&ServerConfig::new("test", "cmd"), &tools, &[]);
        assert!(threats.iter().any(|t| t.title.contains("credential")));
    }

    #[test]
    fn no_false_positive_for_auth_check() {
        let detector = PermissionScopeDetector::new();
        let tools = vec![make_tool(
            "check_auth",
            "Checks if the user is authenticated",
        )];

        let threats = detector.detect(&ServerConfig::new("test", "cmd"), &tools, &[]);
        // Should NOT flag auth checking as credential exposure
        assert!(!threats.iter().any(|t| t.title.contains("credential")));
    }

    #[test]
    fn detects_root_path() {
        let detector = PermissionScopeDetector::new();
        let mut server = ServerConfig::new("test", "npx");
        server.args = vec!["server".to_string(), "/".to_string()];

        let threats = detector.detect(&server, &[], &[]);
        assert!(threats.iter().any(|t| t.id == "PERM-ROOT"));
    }

    #[test]
    fn no_false_positive_for_tmp_path() {
        let detector = PermissionScopeDetector::new();
        let mut server = ServerConfig::new("test", "npx");
        server.args = vec!["server".to_string(), "/tmp".to_string()];

        let threats = detector.detect(&server, &[], &[]);
        // Should NOT flag /tmp as root access
        assert!(!threats.iter().any(|t| t.id == "PERM-ROOT"));
    }
}
