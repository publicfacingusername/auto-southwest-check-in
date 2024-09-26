from __future__ import annotations

import json
import os
import re
import sys
import time
import shutil
import random  # <-- Ensure random is imported
from typing import TYPE_CHECKING, Any, Dict, List

from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import (
    ElementClickInterceptedException,
    NoSuchElementException,
    TimeoutException,
    WebDriverException,
    InvalidArgumentException  # <-- Ensure InvalidArgumentException is imported
)

from .log import LOGS_DIRECTORY, get_logger
from .utils import DriverTimeoutError, LoginError, random_sleep_duration

if TYPE_CHECKING:
    from .checkin_scheduler import CheckInScheduler
    from .reservation_monitor import AccountMonitor

BASE_URL = "https://mobile.southwest.com"
LOGIN_URL = BASE_URL + "/api/security/v4/security/token"
TRIPS_URL = BASE_URL + "/api/mobile-misc/v1/mobile-misc/page/upcoming-trips"
HEADERS_URL = BASE_URL + "/api/chase/v2/chase/offers"

# Southwest's code when logging in with incorrect information
INVALID_CREDENTIALS_CODE = 400518024

WAIT_TIMEOUT_SECS = 180

JSON = Dict[str, Any]

logger = get_logger(__name__)

class WebDriver:
    """
    Controls fetching valid headers for use with the Southwest API.

    This class can be instantiated in two ways:
    1. Setting/refreshing headers before a check-in to ensure the headers are valid.
    2. Logging into an account to retrieve reservations and update headers.
    """

    def __init__(self, checkin_scheduler: CheckInScheduler) -> None:
        self.checkin_scheduler = checkin_scheduler
        self.headers_set = False
        self.debug_screenshots = self._should_take_screenshots()

        # For account login
        self.login_request_id = None
        self.login_status_code = None
        self.trips_request_id = None

    def _should_take_screenshots(self) -> bool:
        """
        Determines if the webdriver should take screenshots for debugging.
        """
        arguments = sys.argv[1:]
        if "--debug-screenshots" in arguments:
            logger.debug("Taking debug screenshots")
            return True
        return False

    def _take_debug_screenshot(self, driver: webdriver.Chrome, name: str) -> None:
        """Take a screenshot of the browser and save it."""
        if self.debug_screenshots:
            screenshot_path = os.path.join(LOGS_DIRECTORY, name)
            driver.save_screenshot(screenshot_path)
            logger.debug(f"Screenshot saved: {screenshot_path}")

    def set_headers(self) -> None:
        """
        Initiates the webdriver to navigate to the Southwest home page and captures the necessary headers.
        """
        driver = self._get_driver()
        self._take_debug_screenshot(driver, "pre_headers.png")
        logger.debug("Navigating to Southwest home page to capture headers")
        driver.get(BASE_URL)

        # Allow some time for the page to load and network requests to be made
        time.sleep(5)

        # Retrieve and parse performance logs to find the headers
        self._parse_performance_logs(driver)

        self._take_debug_screenshot(driver, "post_headers.png")

        driver.quit()

        if not self.headers_set:
            logger.error("Failed to set headers. 'headers_set' attribute not set.")
            raise DriverTimeoutError("Failed to capture headers within the timeout period.")

    def _get_driver(self) -> webdriver.Chrome:
        logger.debug("Starting webdriver for current session")

        # Detect if running on a Raspberry Pi
        if self.is_raspberry_pi():
            logger.debug("Raspberry Pi detected. Using ARM-compatible Chromedriver.")
            chromedriver_path = "/usr/lib/chromium-browser/chromedriver"
            browser_path = "/usr/bin/chromium-browser"
        else:
            logger.debug("Not running on Raspberry Pi. Using default Chromedriver.")
            chromedriver_path = "/usr/lib/chromium-browser/chromedriver"
            browser_path = "chromium"

        # Configure Chrome options
        options = Options()
        options.binary_location = browser_path
        options.add_argument("--headless=new")  # Updated headless flag
        options.add_argument("--disable-gpu")  # Disable GPU acceleration in headless mode
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")  # Overcome limited resource problems
        options.add_argument("--window-size=1920,1080")  # Set window size to avoid element overlap
        options.add_argument("--disable-extensions")
        options.add_argument("--disable-popup-blocking")
        options.add_argument("--disable-infobars")
        options.add_argument("--start-maximized")
        options.add_argument("--disable-blink-features=AutomationControlled")  # Prevent automation detection

        # Set a realistic User-Agent string
        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/116.0.5845.96 Safari/537.36"
        )
        options.add_argument(f"user-agent={user_agent}")

        # Additional options to prevent headless detection
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)

        # Enable Performance Logging via Options
        options.set_capability("goog:loggingPrefs", {"performance": "ALL"})  # <-- Set via options

        # Initialize Selenium Service
        service = Service(executable_path=chromedriver_path)

        # Initialize Chrome WebDriver without desired_capabilities
        try:
            driver = webdriver.Chrome(service=service, options=options)
            logger.debug("Using browser version: %s", driver.capabilities["browserVersion"])

            # Further prevent detection by modifying navigator properties
            driver.execute_cdp_cmd(
                "Page.addScriptToEvaluateOnNewDocument",
                {
                    "source": """
                        Object.defineProperty(navigator, 'webdriver', {
                            get: () => undefined
                        });
                        window.navigator.chrome = {
                            runtime: {},
                            // etc.
                        };
                        Object.defineProperty(navigator, 'plugins', {
                            get: () => [1, 2, 3, 4, 5],
                        });
                        Object.defineProperty(navigator, 'languages', {
                            get: () => ['en-US', 'en'],
                        });
                    """
                },
            )
        except WebDriverException as e:
            logger.error(f"Failed to initialize Chrome WebDriver: {e}")
            raise

        logger.debug("Loading Southwest home page (this may take a moment)")
        return driver

    def _parse_performance_logs(self, driver: webdriver.Chrome) -> None:
        """
        Parses the performance logs to find the response for HEADERS_URL and extracts headers.
        Implements exponential backoff for retries upon encountering 403 or 429 errors.
        """
        max_attempts = 5
        attempt = 0

        while attempt < max_attempts:
            try:
                logs = driver.get_log("performance")
                for entry in logs:
                    log = json.loads(entry["message"])["message"]
                    if log["method"] == "Network.requestWillBeSent":
                        request_url = log["params"]["request"]["url"]
                        if request_url.startswith(HEADERS_URL):
                            request_headers = log["params"]["request"]["headers"]
                            logger.debug(f"Found request for HEADERS_URL: {request_url}")
                            self.checkin_scheduler.headers = self._get_needed_headers(request_headers)
                            self.headers_set = True
                            logger.debug("Headers successfully set from request.")
                            return  # Exit after finding the required headers

                # If headers not found, check for error responses
                for entry in logs:
                    log = json.loads(entry["message"])["message"]
                    if log["method"] == "Network.responseReceived":
                        response_url = log["params"]["response"]["url"]
                        if response_url.startswith(HEADERS_URL):
                            status_code = log["params"]["response"]["status"]
                            if status_code in [403, 429]:
                                raise Exception(f"Encountered HTTP {status_code} while fetching headers.")

                # If headers not found and no errors, wait and retry
                logger.debug("Headers not found in performance logs. Retrying...")
                attempt += 1
                sleep_time = self._calculate_backoff(attempt)
                logger.debug(f"Sleeping for {sleep_time:.2f} seconds before next attempt.")
                time.sleep(sleep_time)

            except Exception as e:
                logger.error(f"Error while parsing performance logs: {e}")
                if attempt < max_attempts - 1:
                    sleep_time = self._calculate_backoff(attempt + 1)
                    logger.debug(f"Sleeping for {sleep_time:.2f} seconds before retrying due to error.")
                    time.sleep(sleep_time)
                    attempt += 1
                else:
                    if self.debug_screenshots:
                        self._take_debug_screenshot(driver, "performance_logs_error.png")
                    raise

        logger.error("Failed to set headers after multiple attempts.")
        raise DriverTimeoutError("Failed to capture headers after multiple attempts.")

    def _calculate_backoff(self, attempt: int) -> float:
        """
        Calculates exponential backoff time with jitter.
        """
        base = 60  # Base wait time in seconds (1 minute)
        cap = 300  # Maximum wait time in seconds (5 minutes)
        sleep_time = min(cap, base * (2 ** (attempt - 1)))
        # Add jitter: random between 0.5x to 1.5x
        sleep_time = sleep_time * random.uniform(0.5, 1.5)
        return sleep_time

    def get_reservations(self, account_monitor: AccountMonitor) -> List[JSON]:
        """
        Logs into the account being monitored to retrieve a list of reservations.
        """
        driver = self._get_driver()
        self._take_debug_screenshot(driver, "pre_login.png")
        logger.debug("Navigating to Southwest home page for login")
        driver.get(BASE_URL)

        # Allow some time for the page to load
        time.sleep(5)

        # Handle any pop-ups that may appear
        self._handle_popup(driver)

        # Take screenshot after handling pop-ups
        self._take_debug_screenshot(driver, "post_popup.png")

        # Start capturing performance logs
        driver.get_log("performance")  # Clear existing logs

        logger.debug("Logging into account to get a list of reservations and valid headers")

        try:
            # Click the login button
            login_button_selector = ".login-button--box"
            WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, login_button_selector))
            ).click()
            logger.debug("Clicked on the login button")
            time.sleep(random_sleep_duration(1, 3))

            # Enter username
            username_selector = 'input[name="userNameOrAccountNumber"]'
            WebDriverWait(driver, 10).until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, username_selector))
            ).send_keys(account_monitor.username)
            logger.debug("Entered username")

            # Enter password
            password_selector = 'input[name="password"]'
            password_field = driver.find_element(By.CSS_SELECTOR, password_selector)
            password_field.send_keys(f"{account_monitor.password}\n")
            logger.debug("Entered password and submitted login form")

            # Allow time for login to process
            time.sleep(5)

            # Parse performance logs to capture headers after login
            self._parse_performance_logs(driver)

            # Handle any post-login pop-ups
            self._handle_popup(driver)

            # Take screenshot after login
            self._take_debug_screenshot(driver, "post_login.png")

            # Check if headers have been set
            if not self.headers_set:
                logger.error("Failed to set headers after login.")
                raise DriverTimeoutError("Failed to capture headers after login.")

            # Fetch reservations
            reservations = self._fetch_reservations(driver)
            driver.quit()
            return reservations

        except Exception as e:
            logger.error(f"An error occurred during login and reservation retrieval: {e}")
            self._take_debug_screenshot(driver, "login_error.png")
            driver.quit()
            raise

    def _handle_popup(self, driver: webdriver.Chrome) -> None:
        """
        Detects and closes the pop-up if it appears.
        """
        try:
            # Wait for the pop-up to appear (if it does)
            popup = WebDriverWait(driver, 5).until(
                EC.visibility_of_element_located((By.CSS_SELECTOR, "div.popup-head"))
            )
            logger.debug("Pop-up detected. Attempting to close it.")

            # Locate the close button within the pop-up
            close_button = popup.find_element(By.CSS_SELECTOR, "button.close-btn")  # Update selector as needed

            # Click the close button
            close_button.click()
            logger.debug("Pop-up closed successfully.")

            # Optionally, wait until the pop-up is no longer visible
            WebDriverWait(driver, 5).until(
                EC.invisibility_of_element_located((By.CSS_SELECTOR, "div.popup-head"))
            )
            logger.debug("Confirmed that the pop-up is no longer visible.")
        except (NoSuchElementException, TimeoutException) as e:
            logger.debug("No pop-up detected or failed to close pop-up: %s", e)
            # If no pop-up is detected, continue without raising an error
        except Exception as e:
            logger.error("An unexpected error occurred while handling pop-up: %s", e)
            self._take_debug_screenshot(driver, "popup_error.png")
            driver.quit()
            raise

    def is_raspberry_pi(self) -> bool:
        """Detect if the system is a Raspberry Pi by checking /proc/cpuinfo."""
        try:
            with open("/proc/cpuinfo", "r") as f:
                info = f.read().lower()
            return "raspberry pi" in info
        except Exception:
            return False

    def _get_needed_headers(self, request_headers: JSON) -> JSON:
        """
        Extracts the necessary headers from the request headers.
        """
        headers = {}
        for header in request_headers:
            if re.match(r"x-api-key|x-channel-id|user-agent|^[\w-]+?-\w$", header, re.I):
                headers[header] = request_headers[header]

        return headers

    def _fetch_reservations(self, driver: webdriver.Chrome) -> List[JSON]:
        """
        Waits for the reservations request to go through and returns only reservations that are flights.
        """
        try:
            # Allow time for network requests to complete
            time.sleep(5)

            logs = driver.get_log("performance")
            reservations = []
            for entry in logs:
                log = json.loads(entry["message"])["message"]
                if log["method"] == "Network.responseReceived":
                    response_url = log["params"]["response"]["url"]
                    if response_url.startswith(TRIPS_URL):
                        request_id = log["params"]["requestId"]
                        logger.debug(f"Found response for TRIPS_URL: {response_url}")

                        # Get the response body
                        response_body = driver.execute_cdp_cmd(
                            "Network.getResponseBody", {"requestId": request_id}
                        )
                        response_content = response_body.get("body", "")

                        # Parse the JSON response
                        try:
                            response_json = json.loads(response_content)
                            upcoming_trips = response_json.get("upcomingTripsPage", [])
                            reservations = [trip for trip in upcoming_trips if trip.get("tripType") == "FLIGHT"]
                            logger.debug(f"Retrieved {len(reservations)} flight reservations.")
                            break  # Exit after finding the reservations
                        except json.JSONDecodeError as jde:
                            logger.error(f"Failed to decode JSON from reservations response: {jde}")
            return reservations
        except Exception as e:
            logger.error(f"Error while fetching reservations: {e}")
            self._take_debug_screenshot(driver, "fetch_reservations_error.png")
            raise
