-- ElevenFlow: xóa toàn bộ proxy cũ + nhập lô 5 gói xoay (dữ liệu từ dashboard nhà cung cấp).
-- Chạy trong Supabase SQL Editor (project đã có bảng proxies + RPC 002/003).
-- Nếu bảng thiếu cột username/password: chạy trước migrations/009_proxies_username_password_if_missing.sql
--
-- Map từ dashboard (ví dụ dòng Http: 103.183.114.120:36173:o2iem:fqy9q):
--   http_host  = phần 1 (IP),  http_port = phần 2 (số cổng HTTP)
--   socks_host = thường cùng IP,       socks_port = cổng Socks (khác HTTP, xem dòng Socks)
--   username   = phần 3,  password = phần 4  (KHÁC "Api key" — api_key chỉ cho changeip 1ip)
-- Cột User/Pass trên web = username / password (cùng giá trị với phần 3 và 4 trong dòng Http).
--
-- Vercel: đặt SKIP_PACKAGE_CHANGEIP=false (hoặc xóa biến) để gọi changeip 1ip.
--         MAX_LEASES_PER_SESSION=3 khớp app 3 worker.

DELETE FROM public.proxies;

INSERT INTO public.proxies
  (label, http_host, http_port, socks_host, socks_port, username, password, api_key, app_id, is_active, last_rotated_at)
VALUES
  ('DC-4G-Random-1m', '103.183.114.120', 36173, '103.183.114.120', 35173,
   'o2iem', 'fqy9q', '5dff244774ffba44d94bf1bfd936c009', '1000', true, '2020-01-01T00:00:00Z'),
  ('Residential-USA-1m', '103.15.95.251', 36654, '103.15.95.251', 35654,
   'z4w6k', 'rtriw', '38c3b34f6eb07cc6a49a9ebc84eba408', '1000', true, '2020-01-01T00:00:00Z'),
  ('Rotate-EU-1m', '103.170.255.148', 36271, '103.170.255.148', 35271,
   'uu6ol', 'n0rnl', 'b2a5c68e6ee569f0967d0a2863e4e9fa', '1000', true, '2020-01-01T00:00:00Z'),
  ('DC-VN-1m', '103.170.254.86', 36315, '103.170.254.86', 35315,
   '7xvvo', 'vdkey', 'b665cca0e5c94cd6841513bc129f6f76', '1000', true, '2020-01-01T00:00:00Z'),
  ('DC-USA-1m', '103.15.95.251', 36021, '103.15.95.251', 35021,
   'lovuk', '81wk3', 'fd5101f2b2ff2fe57aa872f82a885645', '1000', true, '2020-01-01T00:00:00Z');
