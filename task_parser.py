import json

class TaskJSONParser:
    def __init__(self, file_path):
        """
        Initialize the parser and load the JSON file.
        :param file_path: Path to the JSON file.
        """
        self.file_path = file_path
        self.data = self._load_json()
        self.global_frequency = self.data.get("frequency", 20)  # Default to 20 seconds

    def _load_json(self):
        """
        Load JSON data from the file.
        :return: Parsed JSON data as a Python object.
        """
        try:
            with open(self.file_path, 'r') as file:
                return json.load(file)
        except FileNotFoundError:
            raise FileNotFoundError(f"File not found: {self.file_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON format: {e}")

    def get_tasks_for_agent(self, agent_id):
        """
        Get tasks assigned to a specific agent, including the global frequency.

        Args:
            agent_id (str): The ID of the agent.

        Returns:
            list: List of tasks assigned to the agent.
        """
        agent_tasks = []
        for device in self.devices:
            if device.get("assigned_to") == agent_id:
                device["frequency"] = self.global_frequency  # Apply global frequency
                agent_tasks.append(device)
        return agent_tasks


    def get_task_id(self):
        """Get the task ID."""
        return self.data.get("task", {}).get("task_id")

    def get_devices(self):
        """Get the list of devices."""
        return self.data.get("task", {}).get("devices", [])

    def get_device_metrics(self, device_id):
        """
        Get metrics for a specific device.
        :param device_id: The ID of the device.
        :return: Metrics of the device or None if not found.
        """
        devices = self.get_devices()
        for device in devices:
            if device.get("device_id") == device_id:
                return device.get("device_metrics")
        return None

    def update_device_alert_conditions(self, device_id, new_conditions):
        """
        Update alert flow conditions for a specific device.
        :param device_id: The ID of the device.
        :param new_conditions: A dictionary with new alert flow conditions.
        """
        devices = self.get_devices()
        for device in devices:
            if device.get("device_id") == device_id:
                link_metrics = device.get("link_metrics", {})
                if "alertflow_conditions" in link_metrics:
                    link_metrics["alertflow_conditions"].update(new_conditions)
                else:
                    link_metrics["alertflow_conditions"] = new_conditions

    def save(self, output_file=None):
        """
        Save the updated JSON to a file.
        :param output_file: The file to save the data. If None, overwrites the original file.
        """
        save_path = output_file or self.file_path
        with open(save_path, 'w') as file:
            json.dump(self.data, file, indent=4)
