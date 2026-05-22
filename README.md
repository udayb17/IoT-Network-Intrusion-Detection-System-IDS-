## **Project Description – NetScan: IoT Network Intrusion Detection System using Machine Learning**

NetScan is an IoT-based Network Intrusion Detection System (IDS) developed to monitor, analyze, and detect malicious activities in network traffic using machine learning techniques. The project integrates IoT hardware, real-time communication protocols, and intelligent traffic analysis to enhance network security in IoT environments.

The system uses an ESP32 microcontroller programmed in C++ to establish WiFi-based IoT communication and generate real-time network traffic. MQTT (Message Queuing Telemetry Transport) protocol is implemented for lightweight and efficient data transmission between devices and the backend system. The generated traffic data is continuously captured and processed for intrusion detection.

For data analysis and model development, Python is used along with libraries such as Pandas, Scikit-learn, and Scapy. Feature engineering techniques are applied to extract meaningful network attributes including packet length, protocol type, time differences, and packet behavior such as SYN and ACK flags. These features help in identifying abnormal patterns in network traffic.

A Random Forest algorithm is used as the machine learning model because of its high accuracy, ability to handle large datasets efficiently, and reduced risk of overfitting. The model is trained to classify network traffic as either normal or malicious based on the extracted features.

The project also includes a real-time dashboard for live visualization of network traffic, attack detection, and alert generation. Firebase is integrated for deployment and real-time graph synchronization, enabling continuous monitoring and data updates.

Overall, NetScan provides an intelligent and automated solution for intrusion detection by combining IoT technology, real-time monitoring, and machine learning-based traffic classification to improve the security of modern IoT networks.
