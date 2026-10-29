# C++ MasterHub – Backend + Admin Dashboard

Yêu cầu Node >= 22.5 (dùng `node:sqlite` có sẵn, **không cần `npm install`**).

```bash
ADMIN_USERNAME=admin ADMIN_PASSWORD='đặt-mật-khẩu-mạnh' node --no-warnings server.js
# mở http://localhost:3000  (PHẢI mở qua địa chỉ này, không mở file .html trực tiếp)
```

Không đặt `ADMIN_PASSWORD` thì mật khẩu ngẫu nhiên được in ra console một lần.
Admin đầu tiên chỉ được tạo khi cơ sở dữ liệu chưa có Admin nào.

Biến môi trường khác: `PORT` (mặc định 3000), `DB_FILE` (đường dẫn file SQLite),
`COOKIE_SECURE=1` (khi chạy HTTPS), `TRUST_PROXY=1` (khi đứng sau reverse proxy, để ghi đúng IP).

## Cơ sở dữ liệu (SQLite, file `data.sqlite`)
- **Users**: id, username, username_key (UNIQUE), pw_salt, pw_hash (scrypt), **role** (`User` | `Admin`), **device_fp**, signup_ip, created_by, created_at
- **Login_Logs**: id, user_id, username_tried, success, **logged_at**, **device_fp**, ip, user_agent
- **Sessions**: token_hash, user_id, expires_at (cookie HttpOnly + SameSite=Strict)

## API
| Phương thức và đường dẫn | Quyền |
|---|---|
| POST /api/register, POST /api/login, POST /api/logout, GET /api/me | công khai |
| GET /api/admin/devices, GET /api/admin/logs?limit=&offset= | Admin |
| POST /api/admin/admins | Admin |

`/api/register` luôn tạo tài khoản `User`, bỏ qua mọi trường `role` do client gửi.

## Lưu ý
- Device fingerprint chỉ là dấu hiệu nhận diện (băm từ user-agent, màn hình, múi giờ...), có thể trùng hoặc bị giả mạo; chỉ dùng để thống kê.
- Tài khoản cũ lưu trong localStorage không được chuyển lên máy chủ; người dùng cần đăng ký lại.
