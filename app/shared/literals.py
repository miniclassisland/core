"""MINI ClassIsland shared literal constants."""

import re

# ---- System Metadata & Default Configurations ----
SYS_NAME = "MINI ClassIsland Core Management Backend System"
DEFAULT_BASE_DOMAIN = "localminiclassisland.miniopensource.com"
DEFAULT_KEY_FILE = "miniclassisland_server.key"
DEFAULT_ADMIN_SECRET = "change-me"
DEFAULT_CONFIG_DIR = ".miniclassisland"
DEFAULT_CONFIG_FILE = "config.json"
DEFAULT_PID_FILE = "miniclassisland.pid"

# Default Database & Network Allocations
DEFAULT_PG_USER = "postgres"
DEFAULT_PG_PWD = "password"
DEFAULT_PG_ADDR = "localhost:5432"
DEFAULT_PG_DB = "miniclassisland"

DEFAULT_REDIS_ADDR = "localhost:6379"
DEFAULT_REDIS_DB = 0

DEFAULT_CLIENT_PORT = 27041
DEFAULT_MGMT_PORT = 27042
DEFAULT_ADMIN_PORT = 27043
DEFAULT_GRPC_PORT = 27044

PUBLIC_SCHEMA = "public"
REDIS_AUTH_PREFIX = "auth:"
TENANT_ID_KEY = "tenant_id"
SCHEMA_KEY = "schema"


# ---- 1. Security & Auth ----
TOKEN_BYTES = 192
DEFAULT_TTL = 300
GRACE_TTL = 30

RECOVERY_KEY_PREFIX = "recovery_codes"
RECOVERY_CODE_COUNT = 8
RECOVERY_CODE_LENGTH = 8

# Argon2id cost parameters (OWASP recommendations)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64MB
ARGON2_PARALLELISM = 4


# ---- 2. Client Pairing ----
PAIRING_CHARSET = "2346789ABCEFGHJKLMNPRSTWXYZ"
PAIRING_CODE_LEN = 8


# ---- 3. Services Configuration ----
USERNAME_RE = re.compile(r"^[a-z0-9_]{3,64}$")
SLUG_RE = re.compile(r"^[a-z0-9\-]{3,64}$")
SAFE_IDENTIFIER_RE = re.compile(r"^[a-z0-9_\-]+$")

DEFAULT_QUOTAS = [
    ("max_clients", 50),
    ("max_bandwidth_mb", 1024),
    ("feature.ota", 1),
    ("feature.audit", 1),
]

SYSTEM_ROLES = [
    ("banned", "Banned", -1),
    ("pending", "Pending Activation", 0),
    ("normal", "Normal User", 10),
    ("admin", "Administrator", 90),
    ("superadmin", "Super Administrator", 100),
]

ROLE_BANNED = "banned"
ROLE_PENDING = "pending"
ROLE_NORMAL = "normal"
ROLE_ADMIN = "admin"
ROLE_SUPERADMIN = "superadmin"


# ---- 4. Schemas ----
SCHEMA_USERNAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{2,63}$")
SCHEMA_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,62}[a-z0-9]$")
PWD_UPPER = re.compile(r"[A-Z]")
PWD_LOWER = re.compile(r"[a-z]")
PWD_DIGIT = re.compile(r"[0-9]")

ALLOWED_SETTINGS_KEYS = {
    "registration_open",
    "require_approval",
    "max_accounts_per_user",
    "default_role",
    "motd",
}

RESERVED_SUBDOMAINS = {
    "admin",
    "api",
    "www",
    "mail",
    "ftp",
    "ssh",
    "dns",
    "smtp",
    "pop",
    "imap",
    "ntp",
    "snmp",
    "ldap",
    "tcp",
    "udp",
    "system",
    "core",
    "dev",
    "test",
    "staging",
    "prod",
    "auth",
    "login",
}


# ---- 5. Audit Events & Config Types ----
AUDIT_EVENT_NAMES: dict[int, str] = {
    0: "Unspecified",
    1: "AuthorizeSuccess",
    2: "AuthorizeFailed",
    4: "AppSettingsUpdated",
    5: "ClassChangeCompleted",
    6: "ClassPlanUpdated",
    7: "TimeLayoutUpdated",
    8: "SubjectUpdated",
    9: "AppCrashed",
    10: "AppStarted",
    11: "AppExited",
    12: "PluginInstalled",
    13: "PluginUninstalled",
}

CONFIG_TYPE_NAMES: dict[int, str] = {
    0: "Unspecified",
    1: "AppSettings",
    2: "Profile",
    3: "CurrentComponent",
    4: "CurrentAutomation",
    5: "Logs",
    6: "PluginList",
}


# ---- 6. Default Profile Resource Templates ----
DEFAULT_RESOURCES: dict[str, dict[str, dict]] = {
    "Subjects": {
        "default": {
            "Subjects": {
                "sub-chinese": {
                    "Name": "语文",
                    "Initial": "语",
                    "TeacherName": "",
                    "IsOutDoor": False,
                    "AttachedObjects": {},
                },
                "sub-math": {
                    "Name": "数学",
                    "Initial": "数",
                    "TeacherName": "",
                    "IsOutDoor": False,
                    "AttachedObjects": {},
                },
                "sub-english": {
                    "Name": "英语",
                    "Initial": "英",
                    "TeacherName": "",
                    "IsOutDoor": False,
                    "AttachedObjects": {},
                },
            }
        }
    },
    "TimeLayout": {
        "default": {
            "TimeLayouts": {
                "tl-weekday": {
                    "Name": "标准平日作息",
                    "Layouts": [
                        {
                            "StartSecond": "1970-01-01T08:00:00",
                            "EndSecond": "1970-01-01T08:45:00",
                            "TimeType": 0,
                            "IsHideDefault": False,
                            "DefaultClassId": "sub-chinese",
                            "BreakName": "",
                            "ActionSet": None,
                            "AttachedObjects": {},
                        },
                        {
                            "StartSecond": "1970-01-01T08:45:00",
                            "EndSecond": "1970-01-01T08:55:00",
                            "TimeType": 1,
                            "IsHideDefault": False,
                            "DefaultClassId": "",
                            "BreakName": "课间休息",
                            "ActionSet": None,
                            "AttachedObjects": {},
                        },
                        {
                            "StartSecond": "1970-01-01T08:55:00",
                            "EndSecond": "1970-01-01T09:40:00",
                            "TimeType": 0,
                            "IsHideDefault": False,
                            "DefaultClassId": "sub-math",
                            "BreakName": "",
                            "ActionSet": None,
                            "AttachedObjects": {},
                        },
                    ],
                    "AttachedObjects": {},
                }
            }
        }
    },
    "ClassPlan": {
        "default": {
            "ClassPlans": {
                "cp-monday": {
                    "Name": "周一课表",
                    "TimeLayoutId": "tl-weekday",
                    "TimeRule": {
                        "WeekDay": 1,
                        "WeekCountDiv": 0,
                        "WeekCountDivTotal": 2,
                    },
                    "Classes": [
                        {
                            "SubjectId": "sub-chinese",
                            "IsEnabled": True,
                            "AttachedObjects": {},
                        },
                        {
                            "SubjectId": "sub-math",
                            "IsEnabled": True,
                            "AttachedObjects": {},
                        },
                    ],
                    "IsOverlay": False,
                    "OverlaySourceId": None,
                    "OverlaySetupTime": "2026-01-01T00:00:00",
                    "IsEnabled": True,
                    "AssociatedGroup": "00000000-0000-0000-0000-000000000000",
                    "AttachedObjects": {},
                }
            },
            "ClassPlanGroups": {
                "00000000-0000-0000-0000-000000000000": {
                    "Name": "默认课表群",
                    "IsGlobal": False,
                }
            },
        }
    },
    "Policy": {
        "default": {
            "DisableProfileClassPlanEditing": False,
            "DisableProfileTimeLayoutEditing": False,
            "DisableProfileSubjectsEditing": False,
            "DisableProfileEditing": False,
            "DisableSettingsEditing": False,
            "DisableSplashCustomize": False,
            "DisableDebugMenu": False,
            "AllowExitManagement": True,
            "DisableEasterEggs": False,
        }
    },
    "DefaultSettings": {
        "default": {
            "IsWelcomeWindowShowed": True,
            "WindowDockingLocation": 1,
            "WindowDockingOffsetX": 0,
            "WindowDockingOffsetY": 0,
            "WindowLayer": 1,
            "Scale": 1.0,
            "Theme": 0,
            "PrimaryColor": "#0090FF",
            "IsNotificationEnabled": True,
            "IsNotificationEffectEnabled": True,
            "IsNotificationSoundEnabled": True,
            "IsSpeechEnabled": True,
            "SpeechVolume": 1.0,
            "TimeOffsetSeconds": 0.0,
        }
    },
    "Components": {
        "default": {
            "Lines": [
                {
                    "Children": [
                        {
                            "Id": "df3f8295-21f6-482e-bada-fa0e5f14bb66",
                            "NameCache": "日期",
                            "HideOnRule": False,
                            "HidingRules": {"Rules": [], "GroupingMode": 0},
                            "IsResourceOverridingEnabled": False,
                            "MainWindowSecondaryFontSize": 14.0,
                            "MainWindowBodyFontSize": 16.0,
                            "MainWindowEmphasizedFontSize": 18.0,
                            "MainWindowLargeFontSize": 20.0,
                            "IsCustomForegroundColorEnabled": False,
                            "ForegroundColor": "#FFFFFFFF",
                            "IsCustomMarginEnabled": False,
                            "MarginLeft": 0.0,
                            "MarginTop": 0.0,
                            "MarginRight": 0.0,
                            "MarginBottom": 0.0,
                            "HorizontalAlignment": 1,
                            "IsMinWidthEnabled": False,
                            "MinWidth": 100.0,
                            "IsMaxWidthEnabled": False,
                            "MaxWidth": 300.0,
                            "IsFixedWidthEnabled": False,
                            "FixedWidth": 200.0,
                            "Settings": {},
                            "Children": [],
                        },
                        {
                            "Id": "1db2017d-e374-4bc6-9d57-0b4adf03a6b8",
                            "NameCache": "课程表",
                            "HideOnRule": False,
                            "HidingRules": {"Rules": [], "GroupingMode": 0},
                            "IsResourceOverridingEnabled": False,
                            "MainWindowSecondaryFontSize": 14.0,
                            "MainWindowBodyFontSize": 16.0,
                            "MainWindowEmphasizedFontSize": 18.0,
                            "MainWindowLargeFontSize": 20.0,
                            "IsCustomForegroundColorEnabled": False,
                            "ForegroundColor": "#FFFFFFFF",
                            "IsCustomMarginEnabled": False,
                            "MarginLeft": 0.0,
                            "MarginTop": 0.0,
                            "MarginRight": 0.0,
                            "MarginBottom": 0.0,
                            "HorizontalAlignment": 1,
                            "IsMinWidthEnabled": False,
                            "MinWidth": 100.0,
                            "IsMaxWidthEnabled": False,
                            "MaxWidth": 300.0,
                            "IsFixedWidthEnabled": False,
                            "FixedWidth": 200.0,
                            "Settings": {},
                            "Children": [],
                        },
                        {
                            "Id": "9e1af71d-8f77-4b21-a342-448787104dd9",
                            "NameCache": "时钟",
                            "HideOnRule": False,
                            "HidingRules": {"Rules": [], "GroupingMode": 0},
                            "IsResourceOverridingEnabled": False,
                            "MainWindowSecondaryFontSize": 14.0,
                            "MainWindowBodyFontSize": 16.0,
                            "MainWindowEmphasizedFontSize": 18.0,
                            "MainWindowLargeFontSize": 20.0,
                            "IsCustomForegroundColorEnabled": False,
                            "ForegroundColor": "#FFFFFFFF",
                            "IsCustomMarginEnabled": False,
                            "MarginLeft": 0.0,
                            "MarginTop": 0.0,
                            "MarginRight": 0.0,
                            "MarginBottom": 0.0,
                            "HorizontalAlignment": 1,
                            "IsMinWidthEnabled": False,
                            "MinWidth": 100.0,
                            "IsMaxWidthEnabled": False,
                            "MaxWidth": 300.0,
                            "IsFixedWidthEnabled": False,
                            "FixedWidth": 200.0,
                            "Settings": {},
                            "Children": [],
                        },
                    ],
                    "IsMainLine": True,
                    "IsNotificationEnabled": True,
                    "IsHidden": False,
                    "IslandSeparationMode": 0,
                    "HideOnRule": False,
                    "HidingRules": {"Rules": [], "GroupingMode": 0},
                    "IsResourceOverridingEnabled": False,
                    "MainWindowSecondaryFontSize": 14.0,
                    "MainWindowBodyFontSize": 16.0,
                    "MainWindowEmphasizedFontSize": 18.0,
                    "MainWindowLargeFontSize": 20.0,
                    "IsCustomForegroundColorEnabled": False,
                    "ForegroundColor": "#FFFFFFFF",
                    "BackgroundColor": "#00000000",
                    "IsCustomBackgroundColorEnabled": False,
                    "BackgroundOpacity": 0.5,
                    "IsCustomBackgroundOpacityEnabled": False,
                    "CustomCornerRadius": 8.0,
                    "IsCustomCornerRadiusEnabled": False,
                    "Opacity": 1.0,
                }
            ]
        }
    },
    "Credentials": {
        "default": {
            "UserCredential": "",
            "AdminCredential": "",
            "EditPolicyAuthorizeLevel": 2,
            "ExitManagementAuthorizeLevel": 2,
            "EditProfileAuthorizeLevel": 0,
            "EditSettingsAuthorizeLevel": 0,
            "ExitApplicationAuthorizeLevel": 0,
            "EditComponentsAuthorizeLevel": 0,
            "PluginManagementAuthorizeLevel": 0,
        }
    },
}


# ---- 7. HTTP & API Error Messages ----
MSG_USER_NOT_FOUND = "User not found"
MSG_ACCOUNT_NOT_FOUND = "Account not found"
MSG_INVALID_CREDENTIALS = "Invalid username or password"
MSG_UNAUTHORIZED_ACCESS = "Unauthorized access"
MSG_PERMISSION_DENIED = "Permission denied"
MSG_ACCOUNT_SUSPENDED = "Account is suspended or pending approval"
MSG_REGISTRATION_CLOSED = "Self-registration is currently closed"
MSG_USERNAME_EXISTS = "Username already exists"
MSG_EMAIL_EXISTS = "Email address already registered"
MSG_SLUG_EXISTS = "Account slug already in use"
MSG_QUOTA_EXCEEDED = "Quota limit reached"
MSG_INVALID_2FA_CODE = "Invalid 2FA verification code"
MSG_2FA_REQUIRED = "2FA verification code required"
MSG_INVALID_PAIRING_CODE = "Invalid or expired pairing code"
MSG_PAIRING_NOT_FOUND = "Pairing request not found"
MSG_PAIRING_ALREADY_APPROVED = "Pairing request already approved"
MSG_TENANT_NOT_FOUND = "Tenant account not found"
MSG_INVALID_TENANT_CONTEXT = "Invalid tenant context"


# ---- 8. gRPC Status & Error Messages ----
MSG_GRPC_UNAUTHENTICATED = "Unauthenticated gRPC request"
MSG_GRPC_SESSION_INVALID = "Invalid gRPC session token"
MSG_GRPC_CLIENT_NOT_REGISTERED = "Client device not registered"
MSG_GRPC_HANDSHAKE_FAILED = "Handshake verification failed"


# ---- 9. Logging & Formats ----
LOG_FORMAT = "%(asctime)s.%(msecs)03d | %(levelname)-5s | %(port_tag)s | %(name)-30s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
