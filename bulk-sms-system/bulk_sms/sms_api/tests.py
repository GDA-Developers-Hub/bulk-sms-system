import africastalking

username = "sandbox"  # or your live username
api_key = "atsk_d1c4ebc40df7664bc0286fe4cb6c146fba4614e4d27e066bf8422ed4251ff2eea1e005cc"

africastalking.initialize(username, api_key)
sms = africastalking.SMS

response = sms.send(message="Test message", recipients=["+254768049757"])
print(response)
