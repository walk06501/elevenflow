-- Migration 015: xoá hoàn toàn nguồn 1ip.vn (legacy) — theo yêu cầu người
-- dùng, 1ip.vn đã die vĩnh viễn, không còn dùng làm backup nữa. Từ nay pool
-- chỉ còn 2 nguồn: webshare (chính, static) + proxyxoay (backup, xoay qua API).
--
-- Code tương ứng (proxyLease.ts/proxyRotate.ts/adminProxies.ts) đã bỏ hẳn
-- nhánh gọi api.1ip.vn changeip — chạy migration này SAU khi đã deploy code
-- mới, để tránh còn request đang xử lý dựa vào dòng legacy giữa lúc xoá.
--
-- Chạy trong Supabase SQL editor SAU 014_proxyxoay_source.sql.

DELETE FROM public.proxies
 WHERE source IS DISTINCT FROM 'webshare'
   AND source IS DISTINCT FROM 'proxyxoay';
