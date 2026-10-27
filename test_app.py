import hashlib
import hmac
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

os.environ["SMS_HMAC_SECRET"] = "test-secret"
os.environ["SMS_HEARTBEAT_TOKEN"] = "hb-token-0123456789"
os.environ["SMS_DB"] = os.path.join(tempfile.mkdtemp(), "sms.db")

import app  # noqa: E402


class ExtractOtp(unittest.TestCase):
    def test_codes(self):
        cases = {
            "123456 is your OTP for login. Do not share it with anyone.": "123456",
            "Your verification code is 4821.": "4821",
            "G-582913 is your Google verification code.": "582913",
            "Use code 482 913 to sign in": "482913",
            "OTP for txn of Rs 2500.00 on card XX1234 is 739201. Valid 10 mins.": "739201",
            "Dear customer, OTP to authorise INR 15000 at AMAZON is 902811 -HDFC Bank": "902811",
        }
        for text, code in cases.items():
            self.assertEqual(app.extract_otp(text), code, text)

    def test_not_codes(self):
        for text in [
            "Rs 2500 debited from A/c XX1234 on 12-10-26. Avl bal Rs 10432.50",
            "Your order 88213 has shipped",
            "Happy Diwali! Flat 50% off till 2026",
        ]:
            self.assertIsNone(app.extract_otp(text), text)


class Hook(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.init_db()
        cls.server = app.ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        cls.base = "http://127.0.0.1:%d" % cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def post(self, body, secret="test-secret"):
        raw = body.encode()
        sig = hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
        req = urllib.request.Request(self.base + "/hook", raw, {"X-Signature": sig, "Content-Type": "application/json"})
        try:
            return urllib.request.urlopen(req).status
        except urllib.error.HTTPError as e:
            e.close()
            return e.code

    def test_signed_message_is_stored_once(self):
        body = '{\n  "from":"AX-HDFCBK",\n  "text":"Your OTP is 551203",\n  "sentStamp":1761500000000,\n  "receivedStamp":1761500001000,\n  "sim":"sim1"\n}'
        self.assertEqual(self.post(body), 200)
        self.assertEqual(self.post(body), 200)  # phone retry
        msgs = json.load(urllib.request.urlopen(self.base + "/api/messages"))["messages"]
        mine = [m for m in msgs if m["otp"] == "551203"]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["sender"], "AX-HDFCBK")

    def beat(self, token):
        req = urllib.request.Request(self.base + "/heartbeat/" + token, b"", method="POST")
        try:
            return urllib.request.urlopen(req).status
        except urllib.error.HTTPError as e:
            e.close()
            return e.code

    def phone(self):
        return json.load(urllib.request.urlopen(self.base + "/api/messages"))["phone"]

    def test_heartbeat_records_last_seen(self):
        self.assertEqual(self.beat("wrong-token-0123456"), 404)
        self.assertEqual(self.beat("hb-token-0123456789"), 200)
        phone = self.phone()
        self.assertIn("heartbeat_ms", phone)
        self.assertEqual(phone["heartbeat_interval_ms"], 300000)

    def test_sms_records_device_health(self):
        body = '{"from":"VM-ICICI","text":"OTP 112233","receivedStamp":1761500002000,"battery":54,"power":"usb","network":"wifi"}'
        self.assertEqual(self.post(body), 200)
        phone = self.phone()
        self.assertEqual((phone["battery"], phone["power"], phone["network"]), ("54", "usb", "wifi"))
        self.assertIn("sms_ms", phone)

    def test_bad_signature_rejected(self):
        self.assertEqual(self.post('{"from":"x","text":"OTP 999999"}', secret="wrong"), 401)


if __name__ == "__main__":
    unittest.main()
