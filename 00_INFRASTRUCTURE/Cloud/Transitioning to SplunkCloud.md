cloud3du

![[Pasted image 20240905204455.png]]
Token 
66f74bfd-bb6d-4fd1-b4de-0a92926e116c


Token2
eyJraWQiOiJzcGx1bmsuc2VjcmV0IiwiYWxnIjoiSFM1MTIiLCJ2ZXIiOiJ2MiIsInR0eXAiOiJzdGF0aWMifQ.eyJpc3MiOiJzdHVkZW50LTggZnJvbSBzaC1pLTA5MmU3M2ExMmI4NmVhODczIiwic3ViIjoic3R1ZGVudC04IiwiYXVkIjoiQUNTX1Rlc3QiLCJpZHAiOiJTcGx1bmsiLCJqdGkiOiIzYjA3ZWY0YzQ2MTBhMTFmMzk1Yjc1MjFiYTU1ZThhY2U4NDNjOTM4OTNmMjkwM2UwMGQ3YzkwNDFmZmZkZDA0IiwiaWF0IjoxNzI1NjI0NDA1LCJleHAiOjE3MjYwNTY0MDUsIm5iciI6MTcyNTYyNDQwNX0.X7MAXnUVTDWVlcrbFWt4SvKY1h8J9AMga68DyMsAwtQUWt388N4A-refW2XvXM-pE_p_YcleUx8esb0pNIQU6Q

```
curl -X GET "https://admin.splunk.com/$MY_CLOUD/adminconfig/v2/apps/victoria" --header "Authorization: Bearer $MY_TOKEN" -s -S | python -mjson.tool
```

Create a new index:
```
curl -X POST "https://admin.splunk.com/$MY_CLOUD/adminconfig/v2/indexes" --header "Authorization: Bearer $MY_TOKEN" --header "Content-Type: application/json" --data-raw '{"name":"acs_api_test","maxDataSizeMB":1024,"searchableDays":15}'
```

curl -X GET "https://admin.splunk.com/$MY_CLOUD/adminconfig/v2/indexes/acs_api_test" --header "Authorization: Bearer $MY_TOKEN" -s -S | python -mjson.tool

**Best Practices:**
- Limit monitor inputs to same type file, to have only one sourcetype per monitor
