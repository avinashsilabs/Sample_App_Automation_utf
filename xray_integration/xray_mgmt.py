import logging
import os
import re

from xray_integrator.api import get_issue_by_field
from xray_integrator.xray_settings import XraySettings
from xray_integrator.core.models import IssueType
from utf import UtfDatabaseProperties
from utf.env_settings import EnvironSettings

logger = logging.getLogger(__name__)



class XrayMgmtSource:
    """
    Singleton — Xray equivalent of TestRailSource.

    The Jira client and field map are initialised only on the first instantiation.
    Every subsequent call to XrayMgmtSource() returns the same object, so the
    conftest hook can call it naturally without any external state management.

    Usage (anywhere, any number of times):
        props = XrayMgmtSource().fetch_test_results_properties("test_src_map_id", "C102000")
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialised = False
        return cls._instance

    def __init__(self):
        if self._initialised:
            return
        self._initialised = True
        try:
            self._settings = XraySettings()
            self._project_key = self._settings.XRAY_TC_TS_PROJECT_KEY
        except Exception as err:
            logger.warning(f"*** Unable to initialise XrayMgmtSource: {err} ***")
            self._project_key = ""

    @staticmethod
    def _extract_iot_req_id(references_value):
        """
        Extract IOT requirement ID from references field.
        
        Handles formats like:
        - Full URL: 'https://jira-dev.silabs.com/browse/RSCDEV-23075' -> 'RSCDEV-23075'
        - Plain text: 'RSCDEV-23075' -> 'RSCDEV-23075'
        - Multiple IDs: 'IOTREQ-1234, RSCDEV-5678' -> 'IOTREQ-1234'
        
        Uses the VALID_IOT_REQ_NAME_REGEX from environment settings (loaded from release info API).
        Falls back to default patterns if not configured.
        
        Returns the first matching ticket ID or 'na' if none found.
        """
        if not references_value:
            return "na"
        
        # Get regex pattern from environment settings (loaded from release info API)
        env_settings = EnvironSettings()
        regex_pattern = env_settings.get_iot_req_names_regex()
        
        # Fallback to default patterns if not configured
        if not regex_pattern:
            regex_pattern = r'^IOTREQ-[0-9]+|^RSCDEV-[0-9]+|^SI91x-[0-9]+|^SQA_.*-[0-9]+'
            logger.debug(f"VALID_IOT_REQ_NAME_REGEX not set, using default pattern: {regex_pattern}")
        
        # Extract ticket ID from URL or plain text
        # Pattern needs to handle both anchored (^) and non-anchored patterns
        # Remove leading ^ if present since we're searching within text, not matching full string
        search_pattern = regex_pattern.replace('^', '')
        
        matches = re.findall(f'({search_pattern})', str(references_value), re.IGNORECASE)
        if matches:
            return matches[0]  # Return first match
        
        logger.warning(f"No valid IOT requirement ID found in references: '{references_value}' using pattern: '{regex_pattern}'")
        return "na"

    def _get_issue_by_field(
        self, field_name: str, field_value: str, jira_filters: dict = None
    ) -> dict:
        """
        Look up a Jira/Xray issue by a custom field value and return its fields with all
        customfield_XXXXX IDs resolved to human-readable names.

        This method now delegates to xray_integrator's get_issue_by_field API.

        Args:
            field_name:  Human-readable field name as registered in the field map
                         (e.g. 'test_src_map_id', 'case_id').
            field_value: The value to search for (e.g. 'C490482').
            jira_filters: Optional dict of additional Jira field filters
                         (e.g. {"product_line": "WiFi"}).

        Returns:
            dict with human-readable keys and a top-level 'key' entry (the Jira issue key),
            or an empty dict if nothing is found or an error occurs.
        """
        return get_issue_by_field(
            issue_type=IssueType.Test,
            field_name=field_name,
            field_value=field_value,
            additional_filters=jira_filters,
        )

    def fetch_test_results_properties(
        self, field_name: str, field_value: str, jira_filters: dict = None, **kwargs
    ) -> dict:
        """
        Fetch test case properties from Xray by a custom field and map to UtfDatabaseProperties.
        
        Args:
            field_name: Jira field name to search by (e.g., 'test_src_map_id').
            field_value: Value to search for.
            jira_filters: Optional dict of additional Jira field filters passed from conftest.
            **kwargs: Additional properties to override in the result.
        """
        try:
            if not field_value:
                logger.warning("*** field_value param is not provided ***")
                return {}

            if not self._project_key:
                logger.warning("*** Xray project key is not initialised ***")
                return {}

            logger.info(f"Calling Xray API for {field_name}={field_value}")

            issue = self._get_issue_by_field(field_name, field_value, jira_filters)
            if not issue:
                return {}

            # reporter is a dict in Jira; extract display name (equiv: TestRail's created_by.get("name"))
            reporter = issue.get("reporter") or {}
            engineer_name = (
                reporter.get("displayName") or reporter.get("name")
                if isinstance(reporter, dict)
                else reporter
            )

            # Extract and parse iot_req_id from references field (handles URLs and plain text)
            raw_references = issue.get("references")
            parsed_iot_req_id = self._extract_iot_req_id(raw_references)

            database_properties = UtfDatabaseProperties(
                test_case_id=field_value,
                test_result_type=issue.get("test suite type"),
                feature_name=issue.get("feature_name"),
                test_creation_date=issue.get("created"),
                iot_req_id=parsed_iot_req_id,
                product_type=issue.get("product type"),
                product_line=issue.get("product_line"),
                customer_type=issue.get("customer name"),
                test_suite_name=issue.get("technology"),
                test_description=issue.get("summary"),
                engineer_name=engineer_name,
            )
            
            # Update with kwargs, but ensure test_case_version_num is never None
            database_properties = database_properties.copy(update=kwargs)
            if database_properties.test_case_version_num is None:
                database_properties.test_case_version_num = 1  # Default to 1 if not provided need to discuss this and update
            
            logger.info(f"Xray API returned data successfully for {field_name}={field_value}")
            return database_properties.dict()
        except Exception as err:
            logger.error(f"*** Unable to fetch Xray data for {field_name}={field_value}: {err} ***")
            return {}


if __name__ == "__main__":
    os.environ["JIRA_API_TOKEN"] = ""
    os.environ["JIRA_SERVER_URL"] = "https://jira-dev.silabs.com"
    os.environ["XRAY_TC_TS_PROJECT_KEY"] = "SW_SQA_TC"
    source = XrayMgmtSource()
    result = source.fetch_test_results_properties("test_src_map_id", "C102000")
    print("Result:\n", result)
