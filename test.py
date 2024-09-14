import secrets
import datetime

date = datetime.date.today()
print(date)

secret_key = secrets.token_hex(32)

print(secret_key)

for i in  range(100):
    print(i)


if i == 100:
    print('this is inside the if statement')

print('this is outside the if statement')