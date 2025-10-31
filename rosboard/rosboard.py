#!/usr/bin/env python3
import argparse
import asyncio
import importlib
import os
import socket
import threading
import time
import tornado, tornado.web, tornado.websocket
import traceback

# -------------------- ROS Setup --------------------
if os.environ.get("ROS_VERSION") == "1":
    import rospy  # ROS1
elif os.environ.get("ROS_VERSION") == "2":
    import rosboard.rospy2 as rospy  # ROS2
    from rclpy.qos import HistoryPolicy, QoSProfile, QoSReliabilityPolicy, QoSDurabilityPolicy
else:
    print("ROS not detected. Please source your ROS environment\n(e.g. 'source /opt/ros/DISTRO/setup.bash')")
    exit(1)

from rosgraph_msgs.msg import Log
from rosboard.serialization import ros2dict
from rosboard.subscribers.dmesg_subscriber import DMesgSubscriber
from rosboard.subscribers.processes_subscriber import ProcessesSubscriber
from rosboard.subscribers.system_stats_subscriber import SystemStatsSubscriber
from rosboard.subscribers.dummy_subscriber import DummySubscriber
from rosboard.handlers import ROSBoardSocketHandler, NoCacheStaticFileHandler


# ==============================================================
#  ROSBoardNode — main backend server
# ==============================================================

class ROSBoardNode(object):
    instance = None

    def __init__(self, port=8899, node_name="rosboard_backend"):
        """
        Runs the ROSBoard backend. Should be launched by login_server.py
        on port 8899 (default).
        """
        self.__class__.instance = self
        rospy.init_node(node_name)
        self.port = port
        self.title = rospy.get_param("~title", socket.gethostname())

        # Subscriptions tracking
        self.remote_subs = {}  # topic_name -> set of sockets
        self.local_subs = {}   # topic_name -> ROS Subscriber
        self.update_intervals_by_topic = {}  # topic_name -> float (interval in seconds)
        self.last_data_times_by_topic = {}   # topic_name -> float (time in seconds)

        if rospy.__name__ == "rospy2":
            self.sub_rosout = rospy.Subscriber("/rosout", Log, lambda x: x)

        tornado_settings = {
            'debug': True,
            'static_path': os.path.join(os.path.dirname(os.path.realpath(__file__)), 'html')
        }

        tornado_handlers = [
            # 🟢 FIX: Changed from "/rosboard/v1" to "/v1" to match what the proxy forwards
            (r"/v1", ROSBoardSocketHandler, {"node": self}),
            (r"/(.*)", NoCacheStaticFileHandler, {
                "path": tornado_settings.get("static_path"),
                "default_filename": "index.html"
            }),
        ]

        # Tornado web server setup
        self.event_loop = None
        self.tornado_application = tornado.web.Application(tornado_handlers, **tornado_settings)
        asyncio.set_event_loop(asyncio.new_event_loop())
        self.event_loop = tornado.ioloop.IOLoop()
        self.tornado_application.listen(self.port)

        # Logging
        self.logwarn = rospy.logwarn
        self.logerr = rospy.logerr

        # Start threads
        threading.Thread(target=self.event_loop.start, daemon=True).start()
        threading.Thread(target=self.sync_subs_loop, daemon=True).start()
        threading.Thread(target=self.pingpong_loop, daemon=True).start()

        self.lock = threading.Lock()

        rospy.loginfo(f"✅ ROSBoard backend running on :{self.port}")

    # -------------------- Core Loops --------------------

    def start(self):
        rospy.spin()

    def pingpong_loop(self):
        """Send pings to all active sockets every 5 seconds."""
        while True:
            time.sleep(5)
            if self.event_loop is None:
                continue
            try:
                self.event_loop.add_callback(ROSBoardSocketHandler.send_pings)
            except Exception as e:
                rospy.logwarn(str(e))
                traceback.print_exc()

    def sync_subs_loop(self):
        """Periodically calls self.sync_subs()."""
        while True:
            time.sleep(1)
            self.sync_subs()

    # -------------------- Subscriptions --------------------

    def get_msg_class(self, msg_type):
        """Dynamically import and return ROS message class by type string."""
        try:
            msg_module, dummy, msg_class_name = msg_type.replace("/", ".").rpartition(".")
        except ValueError:
            rospy.logerr("invalid type %s" % msg_type)
            return None

        try:
            if not msg_module.endswith(".msg"):
                msg_module = msg_module + ".msg"
            return getattr(importlib.import_module(msg_module), msg_class_name)
        except Exception as e:
            rospy.logerr(str(e))
            return None

    if os.environ.get("ROS_VERSION") == "2":
        def get_topic_qos(self, topic_name: str) -> QoSProfile:
            """Return QoS profile for topic in ROS2."""
            if rospy.__name__ == "rospy2":
                topic_info = rospy._node.get_publishers_info_by_topic(topic_name=topic_name)
                if len(topic_info):
                    if topic_info[0].qos_profile.history == HistoryPolicy.UNKNOWN:
                        topic_info[0].qos_profile.history = HistoryPolicy.KEEP_LAST
                    return topic_info[0].qos_profile
                else:
                    rospy.logwarn(f"No publishers for topic {topic_name}, returning sensor data QoS")
                    return QoSProfile(
                        depth=10,
                        reliability=QoSReliabilityPolicy.BEST_EFFORT,
                        durability=QoSDurabilityPolicy.VOLATILE,
                    )
            else:
                rospy.logwarn("QoS profiles only used in ROS2")
                return None

    # -------------------- Message Handlers --------------------

    def sync_subs(self):
        """Keep local subs synced with remote (websocket) subscriptions."""
        self.lock.acquire()
        try:
            self.all_topics = {}

            for topic_tuple in rospy.get_published_topics():
                topic_name = topic_tuple[0]
                topic_type = topic_tuple[1]
                if type(topic_type) is list:
                    topic_type = topic_type[0]  # ROS2
                self.all_topics[topic_name] = topic_type

            self.event_loop.add_callback(
                ROSBoardSocketHandler.broadcast,
                [ROSBoardSocketHandler.MSG_TOPICS, self.all_topics]
            )

            for topic_name in self.remote_subs:
                if len(self.remote_subs[topic_name]) == 0:
                    continue

                # Handle non-ROS topics
                if topic_name == "_dmesg":
                    if topic_name not in self.local_subs:
                        rospy.loginfo("Subscribing to dmesg [non-ros]")
                        self.local_subs[topic_name] = DMesgSubscriber(self.on_dmesg)
                    continue
                if topic_name == "_system_stats":
                    if topic_name not in self.local_subs:
                        rospy.loginfo("Subscribing to _system_stats [non-ros]")
                        self.local_subs[topic_name] = SystemStatsSubscriber(self.on_system_stats)
                    continue
                if topic_name == "_top":
                    if topic_name not in self.local_subs:
                        rospy.loginfo("Subscribing to _top [non-ros]")
                        self.local_subs[topic_name] = ProcessesSubscriber(self.on_top)
                    continue

                if topic_name not in self.all_topics:
                    rospy.logwarn(f"Warning: topic {topic_name} not found")
                    continue

                # Create new ROS subscriber if needed
                if topic_name not in self.local_subs:
                    topic_type = self.all_topics[topic_name]
                    msg_class = self.get_msg_class(topic_type)
                    if msg_class is None:
                        self.local_subs[topic_name] = DummySubscriber()
                        self.event_loop.add_callback(
                            ROSBoardSocketHandler.broadcast,
                            [
                                ROSBoardSocketHandler.MSG_MSG,
                                {
                                    "_topic_name": topic_name,
                                    "_topic_type": topic_type,
                                    "_error": f"Could not load message type '{topic_type}'. Check if .msg files are sourced.",
                                },
                            ]
                        )
                        continue

                    self.last_data_times_by_topic[topic_name] = 0.0
                    rospy.loginfo(f"Subscribing to {topic_name}")

                    kwargs = {}
                    if rospy.__name__ == "rospy2":
                        kwargs = {"qos": self.get_topic_qos(topic_name)}

                    self.local_subs[topic_name] = rospy.Subscriber(
                        topic_name,
                        msg_class,
                        self.on_ros_msg,
                        callback_args=(topic_name, topic_type),
                        **kwargs
                    )

            # Cleanup
            for topic_name in list(self.local_subs.keys()):
                if topic_name not in self.remote_subs or len(self.remote_subs[topic_name]) == 0:
                    rospy.loginfo(f"Unsubscribing from {topic_name}")
                    self.local_subs[topic_name].unregister()
                    del self.local_subs[topic_name]

        except Exception as e:
            rospy.logwarn(str(e))
            traceback.print_exc()
        self.lock.release()

    # -------------------- Data Forwarding --------------------

    def on_system_stats(self, system_stats):
        if self.event_loop is None:
            return
        msg_dict = {"_topic_name": "_system_stats", "_topic_type": "rosboard_msgs/msg/SystemStats"}
        msg_dict.update(system_stats)
        self.event_loop.add_callback(
            ROSBoardSocketHandler.broadcast, [ROSBoardSocketHandler.MSG_MSG, msg_dict]
        )

    def on_top(self, processes):
        if self.event_loop is None:
            return
        self.event_loop.add_callback(
            ROSBoardSocketHandler.broadcast,
            [
                ROSBoardSocketHandler.MSG_MSG,
                {
                    "_topic_name": "_top",
                    "_topic_type": "rosboard_msgs/msg/ProcessList",
                    "processes": processes,
                },
            ],
        )

    def on_dmesg(self, text):
        if self.event_loop is None:
            return
        self.event_loop.add_callback(
            ROSBoardSocketHandler.broadcast,
            [
                ROSBoardSocketHandler.MSG_MSG,
                {"_topic_name": "_dmesg", "_topic_type": "rcl_interfaces/msg/Log", "msg": text},
            ],
        )

    def on_ros_msg(self, msg, topic_info):
        topic_name, topic_type = topic_info
        t = time.time()
        if t - self.last_data_times_by_topic.get(topic_name, 0) < self.update_intervals_by_topic.get(topic_name, 0) - 1e-4:
            return
        if self.event_loop is None:
            return
        ros_msg_dict = ros2dict(msg)
        ros_msg_dict["_topic_name"] = topic_name
        ros_msg_dict["_topic_type"] = topic_type
        ros_msg_dict["_time"] = time.time() * 1000
        self.last_data_times_by_topic[topic_name] = t
        self.event_loop.add_callback(ROSBoardSocketHandler.broadcast, [ROSBoardSocketHandler.MSG_MSG, ros_msg_dict])


# ==============================================================
#  Entry Point
# ==============================================================

def main(args=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8899, help="Port to run the rosboard backend server on")
    args, unknown = parser.parse_known_args()
    ROSBoardNode(port=args.port).start()


if __name__ == '__main__':
    main()
