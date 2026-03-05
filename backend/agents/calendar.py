"""
Calendar Agent - Adds calendar events with weather information.
Uses WeatherAgent to fetch weather data for events.
"""

import os
from datetime import datetime
from weather_agent import WeatherAgent
from postgresql_agent import PostgreSQLAgent
from agents.auth.agent_auth import AgentAuthenticator, AgentIdentity, AuthResult


class CalendarAgent:
    """Agent that manages calendar events with weather information."""

    AGENT_ID = "calendar_agent"
    PRIVILEGE_LEVEL = "medium"

    def __init__(self):
        """Initialize the Calendar Agent with Weather Agent and PostgreSQL Agent."""
        self.weather_agent = WeatherAgent()
        self.postgresql_agent = PostgreSQLAgent()
        self.events = []  # In-memory storage (replace with actual calendar API in production)

        jwt_secret = os.environ.get("AGENT_JWT_SECRET")
        if not jwt_secret:
            raise EnvironmentError(
                "AGENT_JWT_SECRET environment variable must be set for inter-agent authentication."
            )
        self._authenticator = AgentAuthenticator(jwt_secret=jwt_secret)
        self._identity = AgentIdentity(
            agent_id=self.AGENT_ID,
            agent_name="CalendarAgent",
            privilege_level=self.PRIVILEGE_LEVEL,
            is_internal=False,
        )

    def _get_auth_token(self) -> str:
        """Generate a signed token representing this agent's identity."""
        return self._authenticator.generate_token(self._identity)

    def _verify_outbound_call(self, target_agent: str) -> None:
        """
        Validate the outbound auth token before calling another agent.
        Raises PermissionError if authentication cannot be established.
        """
        token = self._get_auth_token()
        result: AuthResult = self._authenticator.validate_token(token)
        if not result.authenticated:
            raise PermissionError(
                f"CalendarAgent failed to authenticate for inter-agent call to {target_agent}: "
                f"{result.reason}"
            )
        self._authenticator.audit_log(
            action="inter_agent_call",
            caller=self._identity,
            resource=target_agent,
            result=True,
        )
    
    def add_event_with_weather(self, title: str, date: str, time: str, location: str, zipcode: str = None) -> dict:
        """
        Add a calendar event with weather information.
        
        Args:
            title: Event title
            date: Event date (YYYY-MM-DD format)
            time: Event time (HH:MM format)
            location: Event location
            zipcode: Zip code for weather lookup (optional, will try to extract from location if not provided)
        
        Returns:
            Dictionary with event details including weather information
        """
        # Get weather information
        weather_info = None
        if zipcode:
            try:
                self._verify_outbound_call("WeatherAgent")
                weather_info = self.weather_agent.get_weather(zipcode)
            except PermissionError as e:
                print(f"Warning: Authentication failed for WeatherAgent call: {e}")
            except Exception as e:
                print(f"Warning: Could not fetch weather information: {e}")
        elif location:
            # Try to extract zipcode from location (simple heuristic)
            # In production, you might use a geocoding service
            parts = location.split()
            for part in parts:
                if part.isdigit() and len(part) == 5:
                    try:
                        self._verify_outbound_call("WeatherAgent")
                        weather_info = self.weather_agent.get_weather(part)
                        zipcode = part
                        break
                    except PermissionError as e:
                        print(f"Warning: Authentication failed for WeatherAgent call: {e}")
                        break
                    except Exception:
                        continue
        
        # Create event entry
        event = {
            "id": len(self.events) + 1,
            "title": title,
            "date": date,
            "time": time,
            "location": location,
            "zipcode": zipcode,
            "weather": weather_info,
            "created_at": datetime.now().isoformat()
        }
        
        self.events.append(event)
        
        return event
    
    def get_event(self, event_id: int) -> dict:
        """
        Get a calendar event by ID.
        
        Args:
            event_id: Event ID
        
        Returns:
            Event dictionary or None if not found
        """
        for event in self.events:
            if event["id"] == event_id:
                return event
        return None
    
    def list_events(self, date: str = None) -> list:
        """
        List all calendar events, optionally filtered by date.
        
        Args:
            date: Optional date filter (YYYY-MM-DD format)
        
        Returns:
            List of events
        """
        if date:
            return [event for event in self.events if event["date"] == date]
        return self.events
    
    def format_event_display(self, event: dict) -> str:
        """
        Format an event for display with weather information.
        
        Args:
            event: Event dictionary
        
        Returns:
            Formatted string representation
        """
        output = f"""
{'=' * 60}
Event: {event['title']}
Date: {event['date']} at {event['time']}
Location: {event['location']}
"""
        if event.get('zipcode'):
            output += f"Zip Code: {event['zipcode']}\n"
        if event.get('weather'):
            output += f"\nWeather Information:\n{event['weather']}\n"
        output += "=" * 60
        
        return output
    
    def get_employee_info(self, emp_id: int):
        """
        Get employee information (emp_id, emp_name, emp_email) for a specific employee ID.
        Calls PostgreSQLAgent to fetch employee data.
        
        Args:
            emp_id: Employee ID to query
        
        Returns:
            Dictionary containing emp_id, emp_name, emp_email or None if not found
        """
        try:
            self._verify_outbound_call("PostgreSQLAgent")
            if not self.postgresql_agent.connection:
                self.postgresql_agent.connect()

            employee = self.postgresql_agent.get_employee_by_id(emp_id)
            return employee
        except PermissionError as e:
            print(f"Error: Authentication failed for PostgreSQLAgent call: {e}")
            return None
        except Exception as e:
            print(f"Error fetching employee information: {e}")
            return None


def get_employee_54_example():
    """Example: Get employee information for ID 54 using PostgreSQL agent."""
    agent = CalendarAgent()
    print("Calendar Agent - Getting Employee Information")
    print("=" * 60)
    print("\nFetching employee information for ID 54...")
    
    employee = agent.get_employee_info(54)
    if employee:
        print("\n✓ Employee found:")
        print(f"  ID: {employee['emp_id']}")
        print(f"  Name: {employee['emp_name']}")
        print(f"  Email: {employee['emp_email']}")
        return employee
    else:
        print("\n✗ Employee with ID 54 not found.")
        return None


def main():
    """Example usage of the Calendar Agent."""
    agent = CalendarAgent()
    
    print("Calendar Agent - Add Events with Weather Information")
    print("=" * 60)
    
    while True:
        print("\nOptions:")
        print("1. Add event with weather")
        print("2. List all events")
        print("3. View event details")
        print("4. Get employee information (ID 54)")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-4): ").strip()
        
        if choice == "1":
            title = input("Event title: ").strip()
            date = input("Date (YYYY-MM-DD): ").strip()
            time = input("Time (HH:MM): ").strip()
            location = input("Location: ").strip()
            zipcode = input("Zip code (optional): ").strip() or None
            
            event = agent.add_event_with_weather(title, date, time, location, zipcode)
            print("\n✓ Event added successfully!")
            print(agent.format_event_display(event))
            
        elif choice == "2":
            date_filter = input("Filter by date (YYYY-MM-DD, or press Enter for all): ").strip() or None
            events = agent.list_events(date_filter)
            
            if not events:
                print("\nNo events found.")
            else:
                print(f"\nFound {len(events)} event(s):")
                for event in events:
                    print(f"\n[{event['id']}] {event['title']} - {event['date']} at {event['time']} - {event['location']}")
                    
        elif choice == "3":
            event_id = input("Enter event ID: ").strip()
            try:
                event = agent.get_event(int(event_id))
                if event:
                    print(agent.format_event_display(event))
                else:
                    print("Event not found.")
            except ValueError:
                print("Invalid event ID.")
                
        elif choice == "4":
            print("\nFetching employee information for ID 54...")
            employee = agent.get_employee_info(54)
            if employee:
                print("\nEmployee Information:")
                print(f"ID: {employee['emp_id']}")
                print(f"Name: {employee['emp_name']}")
                print(f"Email: {employee['emp_email']}")
            else:
                print("Employee not found.")
                
        elif choice == "5":
            # Close database connection
            agent.postgresql_agent.close()
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()

