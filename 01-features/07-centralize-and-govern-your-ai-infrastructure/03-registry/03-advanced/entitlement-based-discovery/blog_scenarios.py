"""Policies, record metadata, and expected catalogs from the EBD walkthrough."""

IAM_SCHEMA = {
    "type": "object",
    "properties": {
        "stage": {"type": "string", "enum": ["production", "preview"]},
        "under_review": {"type": "boolean"},
    },
}

IAM_POLICY = {
    "version": "1",
    "statements": [
        {
            "sid": "prod-agents",
            "effect": "Allow",
            "principal": {"iam:principalTag/environment": {"StringEquals": "prod"}},
            "resource": {"customMetadata/stage": {"StringEquals": "production"}},
        },
        {
            "sid": "dev-agents",
            "effect": "Allow",
            "principal": {"iam:principalTag/environment": {"StringEquals": "dev"}},
            "resource": {"customMetadata/stage": {"StringEquals": ["production", "preview"]}},
        },
        {
            "sid": "hide-under-review",
            "effect": "Deny",
            "principal": "*",
            "resource": {"customMetadata/under_review": {"Bool": True}},
        },
    ],
}

JWT_SCHEMA = {
    "type": "object",
    "properties": {
        "data_classification": {
            "type": "string",
            "enum": ["financial", "PII", "engineering", "public"],
        },
        "compliance": {"type": "string", "enum": ["SOX", "HIPAA", "Both"]},
        "sensitivity": {"type": "string", "enum": ["low", "medium", "high"]},
    },
}


def sensitivity_statement(sid, agent_sensitivity, record_sensitivities):
    return {
        "sid": sid,
        "effect": "Allow",
        "principal": {"jwt:claim/sensitivity": {"StringEquals": agent_sensitivity}},
        "resource": {
            "customMetadata/data_classification": {"StringEquals": {"ref": "jwt:claim/data_access"}},
            "customMetadata/compliance": {"StringEqualsIfExists": {"ref": "jwt:claim/compliance"}},
            "customMetadata/sensitivity": {"StringEquals": record_sensitivities},
        },
    }


JWT_POLICY = {
    "version": "1",
    "statements": [
        sensitivity_statement("sensitivity-low", "low", ["low"]),
        sensitivity_statement("sensitivity-medium", "medium", ["low", "medium"]),
        sensitivity_statement("sensitivity-high", "high", ["low", "medium", "high"]),
        {
            "sid": "public-tools",
            "effect": "Allow",
            "principal": "*",
            "resource": {"customMetadata/data_classification": {"StringEquals": "public"}},
        },
        {
            "sid": "sox-and-hipaa-tools",
            "effect": "Allow",
            "principal": {
                "jwt:claim/compliance": {"ContainsAll": ["SOX", "HIPAA"]},
                "jwt:claim/sensitivity": {"StringEquals": ["medium", "high"]},
            },
            "resource": {
                "customMetadata/data_classification": {"StringEquals": {"ref": "jwt:claim/data_access"}},
                "customMetadata/compliance": {"StringEquals": "Both"},
                "customMetadata/sensitivity": {"StringEquals": ["low", "medium"]},
            },
        },
    ],
}

IAM_RECORDS = {
    "payments-mcp": {"stage": "production", "under_review": False},
    "search-mcp": {"stage": "production", "under_review": False},
    "code-assistant-mcp": {"stage": "preview", "under_review": False},
    "data-export-mcp": {"stage": "production", "under_review": True},
}

JWT_RECORDS = {
    "budget-forecasting-mcp": {
        "data_classification": "financial",
        "compliance": "SOX",
        "sensitivity": "high",
    },
    "payroll-processing-mcp": {
        "data_classification": "PII",
        "compliance": "SOX",
        "sensitivity": "high",
    },
    "benefits-enrollment-mcp": {
        "data_classification": "PII",
        "compliance": "HIPAA",
        "sensitivity": "medium",
    },
    "benefits-payroll-sync-mcp": {
        "data_classification": "PII",
        "compliance": "Both",
        "sensitivity": "medium",
    },
    "deployment-pipeline-mcp": {
        "data_classification": "engineering",
        "sensitivity": "medium",
    },
    "incident-management-mcp": {
        "data_classification": "engineering",
        "sensitivity": "medium",
    },
    "it-helpdesk-mcp": {"data_classification": "public", "sensitivity": "low"},
}
