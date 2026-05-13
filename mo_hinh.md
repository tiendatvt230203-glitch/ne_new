==========================================================================================
SƠ ĐỒ KẾT NỐI VÀ CHÚ THÍCH INTERFACE CHÍNH XÁC THEO MÔ HÌNH
==========================================================================================

                     === ĐƯỜNG LIÊN KẾT GIỮA HAI SEP (WAN) ===
  
               [ CỔNG enp7s0 ] <=================================> [ CỔNG enp7s0 ]
               +------------------------------------------------------+


               |                                                      |
            +--+---+                                               +--+---+


            | SEP1 |                                               | SEP2 |
            +--+---+                                               +--+---+


               |                                                      |
               +------------------------------------------------------+
               [ CỔNG enp8s0 ] <=================================> [ CỔNG enp8s0 ]



                     === ĐƯỜNG TỪ THIẾT BỊ SEP XUỐNG FIREWALL ===

                     [ THIẾT BỊ SEP1 ]                  [ THIẾT BỊ SEP2 ]

                      |              |                   |              |
         CỔNG enp5s0  |              | CỔNG enp6s0       | CỔNG enp6s0  | CỔNG enp5s0
         (Trống IP)   |              | (Trống IP)        | (Trống IP)   | (Trống IP)

                      |              |                   |              |
                      |              |                   |              |
                      v              v                   v              v
               +--------------+--------------+    +--------------+--------------+

               | Cổng Nhận 1  | Cổng Nhận 2  |    | Cổng Nhận 2  | Cổng Nhận 1  |
               | (Của FW1)    | (Của FW1)    |    | (Của FW2)    | (Của FW2)    |
               |              |              |    |              |              |
               | IP Đặt Tại:  | IP Đặt Tại:  |    | IP Đặt Tại:  | IP Đặt Tại:  |
               |172.16.2.1/24 |172.16.1.1/24 |    |172.16.1.2/24 |172.16.2.2/24 |
               +--------------+--------------+    +--------------+--------------+

               |        THIẾT BỊ FW1         |    |        THIẾT BỊ FW2         |
               +--------------+--------------+    +--------------+--------------+

                              |                                  |
                              | Cổng LAN xuống Máy               | Cổng LAN xuống Máy
                              | (IP: 192.168.9.254/24)           | (IP: 192.168.182.254/24)
                              v                                  v
                       +-------------+                    +-------------+

                       |   Client1   |                    |   Client2   |
                       |192.168.9.1  |                    |192.168.182.1|
                       +-------------+                    +-------------+

==========================================================================================
BẢN MÔ TẢ PHÂN ĐỊNH INTERFACE CHI TIẾT
==========================================================================================

1. BẢN CHẤT PHÍA THIẾT BỊ SEP (CHẠY CHẾ ĐỘ BRIDGE):
------------------------------------------------------------------------------------------
* Bản thân SEP1 và SEP2 chỉ làm nhiệm vụ nối thông cáp (như một sợi dây cáp thông minh).
* Cổng enp5s0 và enp6s0 trên SEP là các cổng vật lý để cắm dây cáp mạng đi xuống Firewall.
* Do chạy Bridge Mode (Lớp 2), các cổng enp5s0 và enp6s0 trên SEP HOÀN TOÀN KHÔNG CÓ IP.

2. BẢN CHẤT PHÍA THIẾT BỊ FIREWALL (NƠI ĐẶT IP 172):
------------------------------------------------------------------------------------------
* Địa chỉ IP 172.16.X.X trong sơ đồ là địa chỉ thuộc về các Interface (Cổng cắm dây) nằm TRÊN FIREWALL.
* Dây cáp cắm từ cổng enp5s0 của SEP1 chạy xuống sẽ cắm vào một cổng trên FW1 -> Bạn đặt IP 172.16.2.1/24 cho cổng đó của FW1.
* Dây cáp cắm từ cổng enp6s0 của SEP1 chạy xuống sẽ cắm vào một cổng khác trên FW1 -> Bạn đặt IP 172.16.1.1/24 cho cổng đó của FW1.
* Tương tự với phía SEP2 và FW2 (IP đặt trên cổng FW2 lần lượt là 172.16.2.2/24 nối về enp5s0 và 172.16.1.2/24 nối về enp6s0).

3. LOGIC GỘP CỔNG TRÊN SEP:
------------------------------------------------------------------------------------------
* Nhóm ảo br0 gộp: Cổng enp5s0 (nối xuống cổng 172.16.2.X của FW) <---> Cổng enp7s0 (nối sang SEP còn lại).
* Nhóm ảo br1 gộp: Cổng enp6s0 (nối xuống cổng 172.16.1.X của FW) <---> Cổng enp8s0 (nối sang SEP còn lại).