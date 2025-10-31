#!/usr/bin/env python3

import rospy
from std_msgs.msg import Float32MultiArray, Bool, Float32

class BatteryMonitor:
    def __init__(self):
        # --- Battery Voltage Range (MUST CONFIGURE) ---
        # Set these to your battery's actual full and empty voltages
        self.MAX_VOLTAGE = 8.4  # Example: 4.2V per cell for a 2S LiPo
        self.MIN_VOLTAGE = 6.4  # Example: 3.2V per cell for a 2S LiPo
        # ----------------------------------------------

        # Voltage divider parameters
        self.R1 = 20000  # 20k ohms
        self.R2 = 10000  # 10k ohms
        self.voltage_divider_ratio = (self.R1 + self.R2) / self.R2  # = 3.0
        
        # Low voltage threshold (for buzzer)
        # This is the ACTUAL battery voltage (e.g. 6.8V), not the raw measured voltage
        self.LOW_VOLTAGE_THRESHOLD = 6.8 # Example: 3.4V per cell
        
        # Initialize ROS node
        rospy.init_node('battery_monitor', anonymous=True)
        
        # Publisher for buzzer control (to Arduino)
        self.buzzer_pub = rospy.Publisher('buzzer_alert', Bool, queue_size=10)
        
        # 🟢 NEW: Publisher for battery percentage
        self.percentage_pub = rospy.Publisher('battery_percentage', Float32, queue_size=10)
        
        # Subscriber for raw battery voltages (from Arduino)
        rospy.Subscriber('battery_voltages', Float32MultiArray, self.battery_callback)
        
        # Battery status variables
        self.battery1_voltage = 0.0
        self.battery2_voltage = 0.0
        self.last_alert_time = 0
        self.alert_interval = 5
        
        rospy.loginfo("Battery Monitor Node Started")
        rospy.loginfo("Voltage Range: %.1fV (Empty) to %.1fV (Full)", self.MIN_VOLTAGE, self.MAX_VOLTAGE)
        rospy.loginfo("Low voltage buzzer threshold: %.1fV", self.LOW_VOLTAGE_THRESHOLD)
        rospy.loginfo("Waiting for battery data...")
    
    def calculate_actual_voltage(self, measured_voltage):
        """Convert measured voltage (after divider) to actual battery voltage"""
        return measured_voltage * self.voltage_divider_ratio
    
    def voltage_to_percentage(self, voltage):
        """Converts a voltage to a percentage 0-100"""
        try:
            percentage = ((voltage - self.MIN_VOLTAGE) / (self.MAX_VOLTAGE - self.MIN_VOLTAGE)) * 100
            # Clamp the value between 0 and 100
            return max(0.0, min(100.0, percentage))
        except ZeroDivisionError:
            # Avoid division by zero if MIN and MAX are the same
            return 0.0

    def battery_callback(self, msg):
        """Callback function for battery voltage messages from Arduino"""
        if len(msg.data) < 2:
            rospy.logwarn("Received message with insufficient data")
            return

        # Get RAW voltages from Arduino (after voltage divider)
        raw_voltage1 = msg.data[0]
        raw_voltage2 = msg.data[1]
        
        # Calculate actual battery voltages
        self.battery1_voltage = self.calculate_actual_voltage(raw_voltage1)
        self.battery2_voltage = self.calculate_actual_voltage(raw_voltage2)
        
        # Calculate average voltage and percentage
        avg_voltage = (self.battery1_voltage + self.battery2_voltage) / 2.0
        percentage = self.voltage_to_percentage(avg_voltage)
        
        # 🟢 NEW: Publish the percentage
        self.percentage_pub.publish(Float32(percentage))
        
        # Display battery information
        self.display_battery_info(avg_voltage, percentage)
        
        # Check for low voltage condition
        self.check_low_voltage()

    def display_battery_info(self, avg_voltage, percentage):
        """Display battery information in terminal"""
        rospy.loginfo("\n" + "="*60)
        rospy.loginfo("BATTERY STATUS: %.1f%% (Avg: %.2fV)", percentage, avg_voltage)
        rospy.loginfo("="*60)
        rospy.loginfo("Battery 1: %.2fV (Actual)", self.battery1_voltage)
        rospy.loginfo("Battery 2: %.2fV (Actual)", self.battery2_voltage)
        rospy.loginfo("="*60)

    def check_low_voltage(self):
        """Check if any battery is below threshold and trigger buzzer"""
        current_time = rospy.get_time()
        
        # Check if EITHER battery is low
        is_low = self.battery1_voltage <= self.LOW_VOLTAGE_THRESHOLD or \
                 self.battery2_voltage <= self.LOW_VOLTAGE_THRESHOLD
        
        if is_low:
            if current_time - self.last_alert_time >= self.alert_interval:
                rospy.logerr("LOW VOLTAGE ALERT! Triggering buzzer...")
                
                buzzer_msg = Bool()
                buzzer_msg.data = True
                self.buzzer_pub.publish(buzzer_msg)
                
                self.last_alert_time = current_time
        else:
            if self.last_alert_time > 0:
                rospy.loginfo("Battery voltage restored to normal levels")
            self.last_alert_time = 0
    
    def run(self):
        """Main loop"""
        rospy.spin()

if __name__ == '__main__':
    try:
        monitor = BatteryMonitor()
        monitor.run()
    except rospy.ROSInterruptException:
        rospy.loginfo("Battery monitor shutdown")
