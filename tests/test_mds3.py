from base64 import b64decode

from fido2.mds3 import MdsAttestationVerifier, parse_blob

# Example data from:
# https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#examples
EXAMPLE_CA = b64decode(
    """
MIIGGTCCBAGgAwIBAgIUdT9qLX0sVMRe8l0sLmHd3mZovQ0wDQYJKoZIhvcNAQEL
BQAwgZsxHzAdBgNVBAMMFkVYQU1QTEUgTURTMyBURVNUIFJPT1QxIjAgBgkqhkiG
9w0BCQEWE2V4YW1wbGVAZXhhbXBsZS5jb20xFDASBgNVBAoMC0V4YW1wbGUgT1JH
MRAwDgYDVQQLDAdFeGFtcGxlMQswCQYDVQQGEwJVUzELMAkGA1UECAwCTVkxEjAQ
BgNVBAcMCVdha2VmaWVsZDAeFw0yMTA0MTkxMTM1MDdaFw00ODA5MDQxMTM1MDda
MIGbMR8wHQYDVQQDDBZFWEFNUExFIE1EUzMgVEVTVCBST09UMSIwIAYJKoZIhvcN
AQkBFhNleGFtcGxlQGV4YW1wbGUuY29tMRQwEgYDVQQKDAtFeGFtcGxlIE9SRzEQ
MA4GA1UECwwHRXhhbXBsZTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAk1ZMRIwEAYD
VQQHDAlXYWtlZmllbGQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDD
jF5wyEWuhwDHsZosGdGFTCcI677rW881vV+UfW38J+K2ioFFNeGVsxbcebK6AVOi
CDPFj0974IpeD9SFOhwAHoDu/LCfXdQWp8ZgQ91ULYWoW8o7NNSp01nbN9zmaO6/
xKNCa0bzjmXoGqglqnP1AtRcWYvXOSKZy1rcPeDv4Dhcpdp6W72fBw0eWIqOhsrI
tuY2/N8ItBPiG03EX72nACq4nZJ/nAIcUbER8STSFPPzvE97TvShsi1FD8aO6l1W
kR/QkreAGjMI++GbB2Qc1nN9Y/VEDbMDhQtxXQRdpFwubTjejkN9hKOtF3B71Yrw
Irng3V9RoPMFdapWMzSlI+WWHog0oTj1PqwJDDg7+z1I6vSDeVWAMKr9mq1w1OGN
zgBopIjd9lRWkRtt2kQSPX9XxqS4E1gDDr8MKbpM3JuubQtNCg9D7Ljvbz6vwvUr
bPHH+oREvucsp0PZ5PpizloepGIcLFxDQqCulGY2n7Ahl0JOFXJqOFCaK3TWHwBv
ZsaY5DgBuUvdUrwtgZNg2eg2omWXEepiVFQn3Fvj43Wh2npPMgIe5P0rwncXvROx
aczd4rtajKS1ucoB9b9iKqM2+M1y/FDIgVf1fWEHwK7YdzxMlgOeLdeV/kqRU5PE
UlLU9a2EwdOErrPbPKZmIfbs/L4B3k4zejMDH3Y+ZwIDAQABo1MwUTAdBgNVHQ4E
FgQU8sWwq1TrurK7xMTwO1dKfeJBbCMwHwYDVR0jBBgwFoAU8sWwq1TrurK7xMTw
O1dKfeJBbCMwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAgEAFw6M
1PiIfCPIBQ5EBUPNmRvRFuDpolOmDofnf/+mv63LqwQZAdo/W8tzZ9kOFhq24SiL
w0H7fsdG/jeREXiIZMNoW/rA6Uac8sU+FYF7Q+qp6CQLlSQbDcpVMifTQjcBk2xh
+aLK9SrrXBqnTAhwS+offGtAW8DpoLuH4tAcQmIjlgMlN65jnELCuqNR/wpA+zch
8LZW8saQ2cwRCwdr8mAzZoLbsDSVCHxQF3/kQjPT7Nao1q2iWcY3OYcRmKrieHDP
67yeLUbVmetfZis2d6ZlkqHLB4ZW1xX4otsEFkuTJA3HWDRsNyhTwx1YoCLsYut5
Zp0myqPNBq28w6qGMyyoJN0Z4RzMEO3R6i/MQNfhK55/8O2HciM6xb5t/aBSuHPK
lBDrFWhpRnKYkaNtlUo35qV5IbKGKau3SdZdSRciaXUd/p81YmoF01UlhhMz/Rqr
1k2gyA0a9tF8+awCeanYt5izl8YO0FlrOU1SQ5UQw4szqqZqbrf4e8fRuU2TXNx4
zk+ImE7WRB44f6mSD746ZCBRogZ/SA5jUBu+OPe4/sEtERWRcQD+fXgce9ZEN0+p
eyJIKAsl5Rm2Bmgyg5IoyWwSG5W+WekGyEokpslou2Yc6EjUj5ndZWz5EiHAiQ74
hNfDoCZIxVVLU3Qbp8a0S1bmsoT2JOsspIbtZUg=
"""
)

# NOTE: Signature changed to be properly ASN.1 formatted!
EXAMPLE_BLOB = """
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDWlRDQ0FndWdBd0lCQWdJQkFUQUtC
Z2dxaGtqT1BRUURBakNCb3pFbk1DVUdBMVVFQXd3ZVJWaEJUVkJNUlNCTlJGTXpJRlJGVTFRZ1NVNVVS
VkpOUlVSSlFWUkZNU0l3SUFZSktvWklodmNOQVFrQkZoTmxlR0Z0Y0d4bFFHVjRZVzF3YkdVdVkyOXRN
UlF3RWdZRFZRUUtEQXRGZUdGdGNHeGxJRTlTUnpFUU1BNEdBMVVFQ3d3SFJYaGhiWEJzWlRFTE1Ba0dB
MVVFQmhNQ1ZWTXhDekFKQmdOVkJBZ01BazFaTVJJd0VBWURWUVFIREFsWFlXdGxabWxsYkdRd0hoY05N
akV3TkRFNU1URXpOVEEzV2hjTk16RXdOREUzTVRFek5UQTNXakNCcFRFcE1DY0dBMVVFQXd3Z1JWaEJU
VkJNUlNCTlJGTXpJRk5KUjA1SlRrY2dRMFZTVkVsR1NVTkJWRVV4SWpBZ0Jna3Foa2lHOXcwQkNRRVdF
MlY0WVcxd2JHVkFaWGhoYlhCc1pTNWpiMjB4RkRBU0JnTlZCQW9NQzBWNFlXMXdiR1VnVDFKSE1SQXdE
Z1lEVlFRTERBZEZlR0Z0Y0d4bE1Rc3dDUVlEVlFRR0V3SlZVekVMTUFrR0ExVUVDQXdDVFZreEVqQVFC
Z05WQkFjTUNWZGhhMlZtYVdWc1pEQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJOUUpz
NndUcWl4YytTK1ZEQWFqRmxQTmF0MTBLRVdKRTVqY1dPdm02cXBPOVNEQUFNWnZiNEhIcnZzK1A1WVJw
SHJTbFVQZHZLK3VFUWJkV2czMVA5dWpMREFxTUFrR0ExVWRFd1FDTUFBd0hRWURWUjBPQkJZRUZMcXNh
cGNYVjRab1ZIQW5ScFBad1FlN1l5MjBNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUM2N3phOEVJdXlS
aUtnTkRYSVAxczFhTHIzanpIOVdWWGZIeDRiSit6Q3NnSWdHL3RWQnV0T0pVVSt2dm9ISW8vb3RBVUFj
SDViTkhQM3VJemlEUytQVFVjPSIsIk1JSUVIekNDQWdlZ0F3SUJBZ0lCQWpBTkJna3Foa2lHOXcwQkFR
c0ZBRENCbXpFZk1CMEdBMVVFQXd3V1JWaEJUVkJNUlNCTlJGTXpJRlJGVTFRZ1VrOVBWREVpTUNBR0NT
cUdTSWIzRFFFSkFSWVRaWGhoYlhCc1pVQmxlR0Z0Y0d4bExtTnZiVEVVTUJJR0ExVUVDZ3dMUlhoaGJY
QnNaU0JQVWtjeEVEQU9CZ05WQkFzTUIwVjRZVzF3YkdVeEN6QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZR
UUlEQUpOV1RFU01CQUdBMVVFQnd3SlYyRnJaV1pwWld4a01CNFhEVEl4TURReE9URXhNelV3TjFvWERU
UTRNRGt3TkRFeE16VXdOMW93Z2FNeEp6QWxCZ05WQkFNTUhrVllRVTFRVEVVZ1RVUlRNeUJVUlZOVUlF
bE9WRVZTVFVWRVNVRlVSVEVpTUNBR0NTcUdTSWIzRFFFSkFSWVRaWGhoYlhCc1pVQmxlR0Z0Y0d4bExt
TnZiVEVVTUJJR0ExVUVDZ3dMUlhoaGJYQnNaU0JQVWtjeEVEQU9CZ05WQkFzTUIwVjRZVzF3YkdVeEN6
QUpCZ05WQkFZVEFsVlRNUXN3Q1FZRFZRUUlEQUpOV1RFU01CQUdBMVVFQnd3SlYyRnJaV1pwWld4a01G
a3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU5HdW1CYlluRlFuVGpQMVJTZmM3MGhzaGdi
aUkxWnRwd1E1bjZ4UkxBL1dxMFBTQ2ZMbDVxUStyN2RsY0sxZDNyM3ZMYSt2bTZHNnZLSEdDUEVlVXpx
TXZNQzB3REFZRFZSMFRCQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVOazZGNFJKbkdHVkZlKzAvY2Jad2Zy
WmQ3WlV3RFFZSktvWklodmNOQVFFTEJRQURnZ0lCQUNucDFmbTBGS2xXbVV0VHBsTHVZZzdtcHM0eFAv
Q091OGRuYjM4dTFuTURWdU9UNCtDWmFpTTlBR3ozMTNHRDIyaGpMR3JtUHVZbjg2d0dPS0kzSE9yRXBz
R2RNbWZ5N3RUbUtYL2VNL2VTM0ZFRFhabkU4MlBuNW9GSXlCVC9mOHNHdVh5T3NGWnFXQnZWZEJJSURs
ZENwRDRteE1RWlpPWnRUcmx2M1d2QlFNQy9kc2ljT3hlM1FLWHZXSGk2UWIvUmh1YWlwM3JQbXdNZis0
SnBuSk8rSk1QcUFhVTFjQUg4SFZzZnJMQU1vS3MxNDhqMitjdmJwYVdtc1Q1cklvSC9lelZyUGFHL01P
aUlncTc5dy9lZnV2U2k1QVg4SitrRG9MU0VmM2Q1d09na0pZQXFVcWNSeFhURUV0S0l6RE02aHphQlFG
aUFXdlRuOUlsVldnbnRRYW1TWHZIK3R4YVRGOWlFbEh4VWY1SU5ZRlZjaUNwenRTcnlkZUh2L09DTlJm
Ny9MVnJpY01TbG84UmgrTzN5UDlWKzJ1TmYzWDhzUUpOdHVmclFOYXFxMTh3aVhsaVRMdWZTbjAyL2cr
bWtoSVVpTktmVE9KcHZDaktlQ25DRmN4UVUyL1hUM0toM0c4Z0RKd3NPNkVWUmpNVUp0NEFZS3plL2hF
VUN3RjU1SUYybTNqSElvQ3U4alZmajI0Q2VFWDVkbmZ2U3IrU1Z2TjVRQjB1WjA1TTRybXlaWHlxQm0w
ekszZlIraUUwL1pwSW51d0xDN1grVzgyelhsbk1rcGxJM1ErSnhkN2pmUTE1U1lORTJLNnJ2UklUMDF3
MFA5WnF5REY3a25HS3BSbHA3T3F4ZDM3YkQvVlViV3BRN2dJQWZzSk5INUtCTG93SEpGRmpXIl19.eyJ
sZWdhbEhlYWRlciI6IlJldHJpZXZhbCBhbmQgdXNlIG9mIHRoaXMgQkxPQiBpbmRpY2F0ZXMgYWNjZXB
0YW5jZSBvZiB0aGUgYXBwcm9wcmlhdGUgYWdyZWVtZW50IGxvY2F0ZWQgYXQgaHR0cHM6Ly9maWRvYWx
saWFuY2Uub3JnL21ldGFkYXRhL21ldGFkYXRhLWxlZ2FsLXRlcm1zLyIsIm5vIjoxNSwibmV4dFVwZGF
0ZSI6IjIwMjAtMDMtMzAiLCJlbnRyaWVzIjpbeyJhYWlkIjoiMTIzNCM1Njc4IiwibWV0YWRhdGFTdGF
0ZW1lbnQiOnsibGVnYWxIZWFkZXIiOiJodHRwczovL2ZpZG9hbGxpYW5jZS5vcmcvbWV0YWRhdGEvbWV
0YWRhdGEtc3RhdGVtZW50LWxlZ2FsLWhlYWRlci8iLCJkZXNjcmlwdGlvbiI6IkZJRE8gQWxsaWFuY2U
gU2FtcGxlIFVBRiBBdXRoZW50aWNhdG9yIiwiYWFpZCI6IjEyMzQjNTY3OCIsImFsdGVybmF0aXZlRGV
zY3JpcHRpb25zIjp7InJ1LVJVIjoi0J_RgNC40LzQtdGAIFVBRiDQsNGD0YLQtdC90YLQuNGE0LjQutC
w0YLQvtGA0LAg0L7RgiBGSURPIEFsbGlhbmNlIiwiZnItRlIiOiJFeGVtcGxlIFVBRiBhdXRoZW50aWN
hdG9yIGRlIEZJRE8gQWxsaWFuY2UifSwiYXV0aGVudGljYXRvclZlcnNpb24iOjIsInByb3RvY29sRmF
taWx5IjoidWFmIiwic2NoZW1hIjozLCJ1cHYiOlt7Im1ham9yIjoxLCJtaW5vciI6MH0seyJtYWpvciI
6MSwibWlub3IiOjF9XSwiYXV0aGVudGljYXRpb25BbGdvcml0aG1zIjpbInNlY3AyNTZyMV9lY2RzYV9
zaGEyNTZfcmF3Il0sInB1YmxpY0tleUFsZ0FuZEVuY29kaW5ncyI6WyJlY2NfeDk2Ml9yYXciXSwiYXR
0ZXN0YXRpb25UeXBlcyI6WyJiYXNpY19mdWxsIl0sInVzZXJWZXJpZmljYXRpb25EZXRhaWxzIjpbW3s
idXNlclZlcmlmaWNhdGlvbk1ldGhvZCI6ImZpbmdlcnByaW50X2ludGVybmFsIiwiYmFEZXNjIjp7InN
lbGZBdHRlc3RlZEZBUiI6MC4wMDAwMiwibWF4UmV0cmllcyI6NSwiYmxvY2tTbG93ZG93biI6MzAsIm1
heFRlbXBsYXRlcyI6NX19XV0sImtleVByb3RlY3Rpb24iOlsiaGFyZHdhcmUiLCJ0ZWUiXSwiaXNLZXl
SZXN0cmljdGVkIjp0cnVlLCJtYXRjaGVyUHJvdGVjdGlvbiI6WyJ0ZWUiXSwiY3J5cHRvU3RyZW5ndGg
iOjEyOCwiYXR0YWNobWVudEhpbnQiOlsiaW50ZXJuYWwiXSwidGNEaXNwbGF5IjpbImFueSIsInRlZSJ
dLCJ0Y0Rpc3BsYXlDb250ZW50VHlwZSI6ImltYWdlL3BuZyIsInRjRGlzcGxheVBOR0NoYXJhY3Rlcml
zdGljcyI6W3sid2lkdGgiOjMyMCwiaGVpZ2h0Ijo0ODAsImJpdERlcHRoIjoxNiwiY29sb3JUeXBlIjo
yLCJjb21wcmVzc2lvbiI6MCwiZmlsdGVyIjowLCJpbnRlcmxhY2UiOjB9XSwiYXR0ZXN0YXRpb25Sb29
0Q2VydGlmaWNhdGVzIjpbIk1JSUNQVENDQWVPZ0F3SUJBZ0lKQU91ZXh2VTNPeTJ3TUFvR0NDcUdTTTQ
5QkFNQ01Ic3hJREFlQmdOVkJBTU1GMU5oYlhCc1pTQkJkSFJsYzNSaGRHbHZiaUJTYjI5ME1SWXdGQVl
EVlFRS0RBMUdTVVJQSUVGc2JHbGhibU5sTVJFd0R3WURWUVFMREFoVlFVWWdWRmRITERFU01CQUdBMVV
FQnd3SlVHRnNieUJCYkhSdk1Rc3dDUVlEVlFRSURBSkRRVEVMTUFrR0ExVUVCaE1DVlZNd0hoY05NVFF
3TmpFNE1UTXpNek15V2hjTk5ERXhNVEF6TVRNek16TXlXakI3TVNBd0hnWURWUVFEREJkVFlXMXdiR1V
nUVhSMFpYTjBZWFJwYjI0Z1VtOXZkREVXTUJRR0ExVUVDZ3dOUmtsRVR5QkJiR3hwWVc1alpURVJNQTh
HQTFVRUN3d0lWVUZHSUZSWFJ5d3hFakFRQmdOVkJBY01DVkJoYkc4Z1FXeDBiekVMTUFrR0ExVUVDQXd
DUTBFeEN6QUpCZ05WQkFZVEFsVlRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVIOGh
2MkQwSFhhNTkvQm1wUTdSWmVoTC9GTUd6RmQxUUJnOXZBVXBPWjNham51UTk0UFI3YU16SDMzblVTQnI
4ZkhZRHJxT0JiNThweEdxSEpSeVgvNk5RTUU0d0hRWURWUjBPQkJZRUZQb0hBM0NMaHhGYkMwSXQ3ekU
0dzhoazVFSi9NQjhHQTFVZEl3UVlNQmFBRlBvSEEzQ0xoeEZiQzBJdDd6RTR3OGhrNUVKL01Bd0dBMVV
kRXdRRk1BTUJBZjh3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUowNlFTWHQ5aWhJYkVLWUtJanNQa3J
pVmRMSWd0ZnNiRFN1N0VySmZ6cjRBaUJxb1lDWmYwK3pJNTVhUWVBSGpJekE5WG02M3JydUF4Qlo5cHM
5ejJYTmxRPT0iXSwiaWNvbiI6ImRhdGE6aW1hZ2UvcG5nO2Jhc2U2NCxpVkJPUncwS0dnb0FBQUFOU1V
oRVVnQUFBRThBQUFBdkNBWUFBQUNpd0pmY0FBQUFBWE5TUjBJQXJzNGM2UUFBQUFSblFVMUJBQUN4and
2OFlRVUFBQUFKY0VoWmN3QUFEc01BQUE3REFjZHZxR1FBQUFhaFNVUkJWR2hEN1pyNWJ4UmxHTWY5S3p
UQjhBTS9ZRWhFMlc3cFFaY1dLS0JjbFNwSEFUbEVMQVJFN2tORUNDQTNGa1dLMENLS1NDRklzS0JjZ1Z
DRFdHTkVTZEFZaWR3Z2dnSkJpUmlNaEZjLzR3eTg4ODR6dTlOZGxuR1RmWkpQMm4zbk8rKzg4OTMzZnZ
lQkJ4K1BxQ3pKa1RVdkJiTG1wVURXdkJUSW1wY0NTWnZYTENkWDlSMDVTazE5YmI1YXRmNTk5ZkcrL2V
yQTU0MXE0N2FQMUxMVmE5U0l5Vk5VaThJaThkNWtHVHNpMzBORnY3YWk5bjdRWlBNd2JkeXMyZXJVMlh
NcVVkeTgrWmNhTm1HaW1FOHlYTjNSVWQzYTE4bkYwZlVsb3ZaKzBDVHpXcGQyVmorZU9tMWJFeXk2RHg
0aTVwVU1HV3ZlbzUwNnEyMjdkdHVXQkl1ZmZyNm9XcFYwRlBOTGhvdzE3NTFObTIxTHZQSDNyVnRXamZ
6NjZMZnFsOHRYN0ZSbDlZRlNYc21Tc2ViOWNlT0diWWs3TU5VY0dQZzhac2JNZTlyZlFVYWFWL0pNWDl
zcWR6RENTdnAwa1pIbVRaZzl4N2JMSGNNblRoYjE2ZUorbVZmUXE4eWFVWlFORzY0aVhaKzAva3E2dU9
aRk8wUXRhdGRXS2ZYblJROTlCajkxUjVPSUZuazU0ak4wbWtVaXFsTzNYRFcrTWwrOThtS0I2dFc3cld
wWmNQYyswemc0dExyWWxVYzg2RTZlR0RqSU11YlZwY3VzZWFyZmdJWUdSazZicmhaVnIvSmNIem9vTDc
1NTBqZWRMRXhvcFdjQXBpMlpVcWh1N0pMdnJWc1FVODF6a3pPUGVlbU1SWXZWdVFzWDdQYmlEUVk1SnZ
ab25mdEsrMVZZOEg5dXR4NTMwaDBvYitqbVJZcWo2b3VhWXZFZW5XL1dsWWpwOGN3Yk1tNjgydFB3cVc
xUjR0ai8yU0gxM0lSSllsNG1vWnZYcGlTcURyN2RYdFFIeGEvUEszLytCV3NLMWRUZ0h1NlY4dFFKM2J
3Rmt3cEZyVU9RNTBzMXIzbGV2bTh6WmNxMTcrQkJhdzdLOGxFSzVxemtZZWFyazlBOHA3UDNHekRLK25
kM0RRb3crNlVDOFNWTjgyaXV2MzhpbTdOdGFYdFYxQ1ZxNlJndzRwa3NtYmRpM2J1MkRlN1lmYUJCeGN
xZnZxUHJVakZRTlRRMjJsZmRVVlZUNjhyVEpLRjVEblNtVWpnZHFnNG1TUzlwbXNmREpSM0c2VG9IMGl
XOWFWN0xXTEhZWEtsbFREdDBMVEF0a1lJYWFtcDFRalZ2Kyt1eUdVeFZkSjBETlZYU20rYjFxUnhwbDg
0ZGRmWDFMcDFPL2Q2OXRzb2QwdnM1aEdyZTl4dThvK2ZwTFIxY0doTlRENlo1N0M5S01XWGVmSmRPWjk
0YmI5b3FkMVJPblM3cUlUVHpIaW1NcWl2Yk8zZzBEZFZ5azNXUUJoQnp0SzM1WUtOZE9uYzhPM2FjUzZ
mRFpGZ0thWExzRUpwNXJkcmxpQnFwODljSmNzL203VHZzMHJrakdmTjRiMGtQb1puM1VKdUlPcm5aMjJ
5UDFmbXZVeCtPNWdTcWViVjFtK3pTdVlOVmhxN1RXYkRpTFZ2bGpwbExsb3A2Q0xYUCsycXR2R0xJTC8
xdmltSVNkTUJnelNvRlp5dTZUcWQranp4Z3NQYVY5QkNxZWUvTmpZazZ2NmxLOWN3aVVjL1NUdGYxSER
wTTNiNTkyeTdoM1RoeDVveks2OUhMcFlXdUF3YXFTNWN2MjZxN2NlYjhlZlZZYVJlUDNpRlU4emoxa25
Td1pYSE1tbkNqWTBPZ2FsbzdVUWZTQ00zcVFRcjJIL1hGUDdzc1h4NDVZbDkxQnllQ2VwNG1vWm9IKzF
mRzN4RDR0VDd4OGt3eWo4bndiOWV2MjZWMEI2ZCs3SDR6S3Z1ZEFINTM3RmpxeXpPSGRKbkhFdXptWHE
vV2p4T2J2Tk1idjduaHl3c1gyYVZzV3RDOCs0OGFMZWFwRTdwNXdLWmkwQTJBUVJWNW52UjRFK3VKYyt
iNjFrQXBxSW54QmdtZC80VjVRUC9tdDE4SERDN3NSSGZ0bWV1NWxtaFYwcm4vQUxYMjMyYnFkNEJGbkR
4N1ZpMWNXUzJ1ZmYwSWJCNDdxZXh4bVVqOVF1dFlqdXBkM3RZRDZhYldCQk1yaCthcE5iT0tyTkYxK3V
nQ2E0cmlYR2Z3TVBQdFZpYXZoVTNZTU9BQW51VWIvUjA3TDB5T1NlT2FkRTg4QXBzWEZHZmYzMHluaGx
KZ001MUNVNnZOOUV6Z25wdkhCRlV5aVZyYWVQaXdKNTNERjVaVFpub21FTmc4NWtOVWQyb0ppMldwcjR
PbW1rZk40eDR6SGZpVkZjOER2OE56dWhOcU9pZGlsR3ZBNkRHdWVad083OEFBUW42Y2lFazYrcnc1VmN
2anZxTkRZUE9vSVV3YUtTaHJ4QXVYTGxrSDRhWXVHZk1ZRGMxMFdGNVRhMzFoUEpPZmNVaHJVL0psSU5
pNmM2ZWxSWWRCcG82KytZZmp4NjFsR05mUm00TUQ1ckoxajNGb0dIbmpEU0JOYXJZVWdNTHlNc3pLcGI
3dFhwb0hmUHM4aDNXcDFMek5mTms1NFh4QzF3REdVbVl6WFllZmg2ei9jS3RWbTRFQnhhOVZRR0R6WXI
zTHJVTVJqSEVLa2s3emFGS1lRQTJoR1FVMXorODVORldwWERya3ozdngxMEdxeFE2QnplTmJvQms1bjh
rNG5lYlJoK2sxaFdmeFRGMEQxRXlXVXM1bnYrZGdRcUtheHp1Q2RFMGlzSGwwMk5ROGFoMG1YcjEyTGE
zbTBmOXdpazkrd0xOVE1ZLzg2TVBvOHlpMzFPZnhtVDZQV29xRzkrRFp1a1luYTU2bVNadDVXV1N5NXF
WQTFyd1V5SnFYQWxuemtpYWkvZ0hTRDdSa1R5aWhvZ0FBQUFCSlJVNUVya0pnZ2c9PSJ9LCJzdGF0dXN
SZXBvcnRzIjpbeyJzdGF0dXMiOiJGSURPX0NFUlRJRklFRCIsImVmZmVjdGl2ZURhdGUiOiIyMDE0LTA
xLTA0In1dLCJ0aW1lT2ZMYXN0U3RhdHVzQ2hhbmdlIjoiMjAxNC0wMS0wNCJ9LHsiYWFndWlkIjoiMDE
zMmQxMTAtYmY0ZS00MjA4LWE0MDMtYWI0ZjVmMTJlZmU1IiwibWV0YWRhdGFTdGF0ZW1lbnQiOnsibGV
nYWxIZWFkZXIiOiJodHRwczovL2ZpZG9hbGxpYW5jZS5vcmcvbWV0YWRhdGEvbWV0YWRhdGEtc3RhdGV
tZW50LWxlZ2FsLWhlYWRlci8iLCJkZXNjcmlwdGlvbiI6IkZJRE8gQWxsaWFuY2UgU2FtcGxlIEZJRE8
yIEF1dGhlbnRpY2F0b3IiLCJhYWd1aWQiOiIwMTMyZDExMC1iZjRlLTQyMDgtYTQwMy1hYjRmNWYxMmV
mZTUiLCJhbHRlcm5hdGl2ZURlc2NyaXB0aW9ucyI6eyJydS1SVSI6ItCf0YDQuNC80LXRgCBGSURPMiD
QsNGD0YLQtdC90YLQuNGE0LjQutCw0YLQvtGA0LAg0L7RgiBGSURPIEFsbGlhbmNlIiwiZnItRlIiOiJ
FeGVtcGxlIEZJRE8yIGF1dGhlbnRpY2F0b3IgZGUgRklETyBBbGxpYW5jZSIsInpoLUNOIjoi5L6G6Ie
qRklETyBBbGxpYW5jZeeahOekuuS-i0ZJRE8y6Lqr5Lu96amX6K2J5ZmoIn0sInByb3RvY29sRmFtaWx
5IjoiZmlkbzIiLCJzY2hlbWEiOjMsImF1dGhlbnRpY2F0b3JWZXJzaW9uIjo1LCJ1cHYiOlt7Im1ham9
yIjoxLCJtaW5vciI6MH1dLCJhdXRoZW50aWNhdGlvbkFsZ29yaXRobXMiOlsic2VjcDI1NnIxX2VjZHN
hX3NoYTI1Nl9yYXciLCJyc2Fzc2FfcGtjc3YxNV9zaGEyNTZfcmF3Il0sInB1YmxpY0tleUFsZ0FuZEV
uY29kaW5ncyI6WyJjb3NlIl0sImF0dGVzdGF0aW9uVHlwZXMiOlsiYmFzaWNfZnVsbCJdLCJ1c2VyVmV
yaWZpY2F0aW9uRGV0YWlscyI6W1t7InVzZXJWZXJpZmljYXRpb25NZXRob2QiOiJub25lIn1dLFt7InV
zZXJWZXJpZmljYXRpb25NZXRob2QiOiJwcmVzZW5jZV9pbnRlcm5hbCJ9XSxbeyJ1c2VyVmVyaWZpY2F
0aW9uTWV0aG9kIjoicGFzc2NvZGVfZXh0ZXJuYWwiLCJjYURlc2MiOnsiYmFzZSI6MTAsIm1pbkxlbmd
0aCI6NH19XSxbeyJ1c2VyVmVyaWZpY2F0aW9uTWV0aG9kIjoicGFzc2NvZGVfZXh0ZXJuYWwiLCJjYUR
lc2MiOnsiYmFzZSI6MTAsIm1pbkxlbmd0aCI6NH19LHsidXNlclZlcmlmaWNhdGlvbk1ldGhvZCI6InB
yZXNlbmNlX2ludGVybmFsIn1dXSwia2V5UHJvdGVjdGlvbiI6WyJoYXJkd2FyZSIsInNlY3VyZV9lbGV
tZW50Il0sIm1hdGNoZXJQcm90ZWN0aW9uIjpbIm9uX2NoaXAiXSwiY3J5cHRvU3RyZW5ndGgiOjEyOCw
iYXR0YWNobWVudEhpbnQiOlsiZXh0ZXJuYWwiLCJ3aXJlZCIsIndpcmVsZXNzIiwibmZjIl0sInRjRGl
zcGxheSI6W10sImF0dGVzdGF0aW9uUm9vdENlcnRpZmljYXRlcyI6WyJNSUlDUFRDQ0FlT2dBd0lCQWd
JSkFPdWV4dlUzT3kyd01Bb0dDQ3FHU000OUJBTUNNSHN4SURBZUJnTlZCQU1NRjFOaGJYQnNaU0JCZEh
SbGMzUmhkR2x2YmlCU2IyOTBNUll3RkFZRFZRUUtEQTFHU1VSUElFRnNiR2xoYm1ObE1SRXdEd1lEVlF
RTERBaFZRVVlnVkZkSExERVNNQkFHQTFVRUJ3d0pVR0ZzYnlCQmJIUnZNUXN3Q1FZRFZRUUlEQUpEUVR
FTE1Ba0dBMVVFQmhNQ1ZWTXdIaGNOTVRRd05qRTRNVE16TXpNeVdoY05OREV4TVRBek1UTXpNek15V2p
CN01TQXdIZ1lEVlFRRERCZFRZVzF3YkdVZ1FYUjBaWE4wWVhScGIyNGdVbTl2ZERFV01CUUdBMVVFQ2d
3TlJrbEVUeUJCYkd4cFlXNWpaVEVSTUE4R0ExVUVDd3dJVlVGR0lGUlhSeXd4RWpBUUJnTlZCQWNNQ1Z
CaGJHOGdRV3gwYnpFTE1Ba0dBMVVFQ0F3Q1EwRXhDekFKQmdOVkJBWVRBbFZUTUZrd0V3WUhLb1pJemo
wQ0FRWUlLb1pJemowREFRY0RRZ0FFSDhodjJEMEhYYTU5L0JtcFE3UlplaEwvRk1HekZkMVFCZzl2QVV
wT1ozYWpudVE5NFBSN2FNekgzM25VU0JyOGZIWURycU9CYjU4cHhHcUhKUnlYLzZOUU1FNHdIUVlEVlI
wT0JCWUVGUG9IQTNDTGh4RmJDMEl0N3pFNHc4aGs1RUovTUI4R0ExVWRJd1FZTUJhQUZQb0hBM0NMaHh
GYkMwSXQ3ekU0dzhoazVFSi9NQXdHQTFVZEV3UUZNQU1CQWY4d0NnWUlLb1pJemowRUF3SURTQUF3UlF
JaEFKMDZRU1h0OWloSWJFS1lLSWpzUGtyaVZkTElndGZzYkRTdTdFckpmenI0QWlCcW9ZQ1pmMCt6STU
1YVFlQUhqSXpBOVhtNjNycnVBeEJaOXBzOXoyWE5sUT09Il0sImljb24iOiJkYXRhOmltYWdlL3BuZzt
iYXNlNjQsaVZCT1J3MEtHZ29BQUFBTlNVaEVVZ0FBQUU4QUFBQXZDQVlBQUFDaXdKZmNBQUFBQVhOU1I
wSUFyczRjNlFBQUFBUm5RVTFCQUFDeGp3djhZUVVBQUFBSmNFaFpjd0FBRHNNQUFBN0RBY2R2cUdRQUF
BYWhTVVJCVkdoRDdacjVieFJsR01mOUt6VEI4QU0vWUVoRTJXN3BRWmNXS0tCY2xTcEhBVGxFTEFSRTd
rTkVDQ0EzRmtXSzBDS0tTQ0ZJc0tCY2dWQ0RXR05FU2RBWWlkd2dnZ0pCaVJpTWhGYy80d3k4ODg0enU
5TmRsbkdUZlpKUDJuM25PKys4ODkzM2Z2ZUJCeCtQcUN6SmtUVXZCYkxtcFVEV3ZCVEltcGNDU1p2WEx
DZFg5UjA1U2sxOWJiNWF0ZjU5OWZHKy9lckE1NDFxNDdhUDFMTFZhOVNJeVZOVWk4SWk4ZDVrR1RzaTM
wTkZ2N2FpOW43UVpQTXdiZHlzMmVyVTJYTXFVZHk4K1pjYU5tR2ltRTh5WE4zUlVkM2ExOG5GMGZVbG9
2WiswQ1R6V3BkMlZqK2VPbTFiRXl5NkR4NGk1cFVNR1d2ZW81MDZxMjI3ZHR1V0JJdWZmcjZvV3BWMEZ
QTkxob3cxNzUxTm0yMUx2UEgzclZ0V2pmejY2TGZxbDh0WDdGUmw5WUZTWHNtU3NlYjljZU9HYllrN01
OVWNHUGc4WnNiTWU5cmZRVWFhVi9KTVg5c3FkekRDU3ZwMGtaSG1UWmc5eDdiTEhjTW5UaGIxNmVKK21
WZlFxOHlhVVpRTkc2NGlYWiswL2txNnVPWkZPMFF0YXRkV0tmWG5SUTk5Qmo5MVI1T0lGbms1NGpOMG1
rVWlxbE8zWERXK01sKzk4bUtCNnRXN3JXcFpjUGMrMHpnNHRMcllsVWM4NkU2ZUdEaklNdWJWcGN1c2V
hcmZnSVlHUms2YnJoWlZyL0pjSHpvb0w3NTUwamVkTEV4b3BXY0FwaTJaVXFodTdKTHZyVnNRVTgxemt
6T1BlZW1NUll2VnVRc1g3UGJpRFFZNUp2Wm9uZnRLKzFWWThIOXV0eDUzMGgwb2Iram1SWXFqNm91YVl
2RWVuVy9XbFlqcDhjd2JNbTY4MnRQd3FXMVI0dGovMlNIMTNJUkpZbDRtb1p2WHBpU3FEcjdkWHRRSHh
hL1BLMy8rQldzSzFkVGdIdTZWOHRRSjNid0Zrd3BGclVPUTUwczFyM2xldm04elpjcTE3K0JCYXc3Szh
sRUs1cXprWWVhcms5QThwN1AzR3pESytuZDNEUW93KzZVQzhTVk44Mml1djM4aW03TnRhWHRWMUNWcTZ
SZ3c0cGtzbWJkaTNidTJEZTdZZmFCQnhjcWZ2cVByVWpGUU5UUTIybGZkVVZWVDY4clRKS0Y1RG5TbVV
qZ2RxZzRtU1M5cG1zZkRKUjNHNlRvSDBpVzlhVjdMV0xIWVhLbGxURHQwTFRBdGtZSWFhbXAxUWpWdis
rdXlHVXhWZEowRE5WWFNtK2IxcVJ4cGw4NGRkZlgxTHAxTy9kNjl0c29kMHZzNWhHcmU5eHU4bytmcEx
SMWNHaE5URDZaNTdDOUtNV1hlZkpkT1o5NGJiOW9xZDFST25TN3FJVFR6SGltTXFpdmJPM2cwRGRWeWs
zV1FCaEJ6dEszNVlLTmRPbmM4TzNhY1M2ZkRaRmdLYVhMc0VKcDVyZHJsaUJxcDg5Y0pjcy9tN1R2czB
ya2pHZk40YjBrUG9abjNVSnVJT3JuWjIyeVAxZm12VXgrTzVnU3FlYlYxbSt6U3VZTlZocTdUV2JEaUx
WdmxqcGxMbG9wNkNMWFArMnF0dkdMSUwvMXZpbUlTZE1CZ3pTb0ZaeXU2VHFkK2p6eGdzUGFWOUJDcWV
lL05qWWs2djZsSzljd2lVYy9TVHRmMUhEcE0zYjU5Mnk3aDNUaHg1b3pLNjlITHBZV3VBd2FxUzVjdjI
2cTdjZWI4ZWZWWWFSZVAzaUZVOHpqMWtuU3daWEhNbW5DalkwT2dhbG83VVFmU0NNM3FRUXIySC9YRlA
3c3NYeDQ1WWw5MUJ5ZUNlcDRtb1pvSCsxZkczeEQ0dFQ3eDhrd3lqOG53YjlldjI2VjBCNmQrN0g0ekt
2dWRBSDUzN0ZqcXl6T0hkSm5IRXV6bVhxL1dqeE9idk5NYnY3bmh5d3NYMmFWc1d0QzgrNDhhTGVhcEU
3cDV3S1ppMEEyQVFSVjVudlI0RSt1SmMrYjYxa0FwcUlueEJnbWQvNFY1UVAvbXQxOEhEQzdzUkhmdG1
ldTVsbWhWMHJuL0FMWDIzMmJxZDRCRm5EeDdWaTFjV1MydWZmMEliQjQ3cWV4eG1VajlRdXRZanVwZDN
0WUQ2YWJXQkJNcmgrYXBOYk9Lck5GMSt1Z0NhNHJpWEdmd01QUHRWaWF2aFUzWU1PQUFudVViL1IwN0w
weU9TZU9hZEU4OEFwc1hGR2ZmMzB5bmhsSmdNNTFDVTZ2TjlFemducHZIQkZVeWlWcmFlUGl3SjUzREY
1WlRabm9tRU5nODVrTlVkMm9KaTJXcHI0T21ta2ZONHg0ekhmaVZGYzhEdjhOenVoTnFPaWRpbEd2QTZ
ER3VlWndPNzhBQVFuNmNpRWs2K3J3NVZjdmp2cU5EWVBPb0lVd2FLU2hyeEF1WExsa0g0YVl1R2ZNWUR
jMTBXRjVUYTMxaFBKT2ZjVWhyVS9KbElOaTZjNmVsUllkQnBvNisrWWZqeDYxbEdOZlJtNE1ENXJKMWo
zRm9HSG5qRFNCTmFyWVVnTUx5TXN6S3BiN3RYcG9IZlBzOGgzV3AxTHpOZk5rNTRYeEMxd0RHVW1Zelh
ZZWZoNnovY0t0Vm00RUJ4YTlWUUdEellyM0xyVU1SakhFS2trN3phRktZUUEyaEdRVTF6Kzg1TkZXcFh
Ecmt6M3Z4MTBHcXhRNkJ6ZU5ib0JrNW44azRuZWJSaCtrMWhXZnhURjBEMUV5V1VzNW52K2RnUXFLYXh
6dUNkRTBpc0hsMDJOUThhaDBtWHIxMkxhM20wZjl3aWs5K3dMTlRNWS84Nk1Qbzh5aTMxT2Z4bVQ2UFd
vcUc5K0RadWtZbmE1Nm1TWnQ1V1dTeTVxVkExcndVeUpxWEFsbnpraWFpL2dIU0Q3UmtUeWlob2dBQUF
BQkpSVTVFcmtKZ2dnPT0iLCJzdXBwb3J0ZWRFeHRlbnNpb25zIjpbeyJpZCI6ImhtYWMtc2VjcmV0Iiw
iZmFpbF9pZl91bmtub3duIjpmYWxzZX0seyJpZCI6ImNyZWRQcm90ZWN0IiwiZmFpbF9pZl91bmtub3d
uIjpmYWxzZX1dLCJhdXRoZW50aWNhdG9yR2V0SW5mbyI6eyJ2ZXJzaW9ucyI6WyJVMkZfVjIiLCJGSUR
PXzJfMCJdLCJleHRlbnNpb25zIjpbImNyZWRQcm90ZWN0IiwiaG1hYy1zZWNyZXQiXSwiYWFndWlkIjo
iMDEzMmQxMTBiZjRlNDIwOGE0MDNhYjRmNWYxMmVmZTUiLCJvcHRpb25zIjp7InBsYXQiOiJmYWxzZSI
sInJrIjoidHJ1ZSIsImNsaWVudFBpbiI6InRydWUiLCJ1cCI6InRydWUiLCJ1diI6InRydWUiLCJ1dlR
va2VuIjoiZmFsc2UiLCJjb25maWciOiJmYWxzZSJ9LCJtYXhNc2dTaXplIjoxMjAwLCJwaW5VdkF1dGh
Qcm90b2NvbHMiOlsxXSwibWF4Q3JlZGVudGlhbENvdW50SW5MaXN0IjoxNiwibWF4Q3JlZGVudGlhbEl
kTGVuZ3RoIjoxMjgsInRyYW5zcG9ydHMiOlsidXNiIiwibmZjIl0sImFsZ29yaXRobXMiOlt7InR5cGU
iOiJwdWJsaWMta2V5IiwiYWxnIjotN30seyJ0eXBlIjoicHVibGljLWtleSIsImFsZyI6LTI1N31dLCJ
tYXhBdXRoZW50aWNhdG9yQ29uZmlnTGVuZ3RoIjoxMDI0LCJkZWZhdWx0Q3JlZFByb3RlY3QiOjIsImZ
pcm13YXJlVmVyc2lvbiI6NX19LCJzdGF0dXNSZXBvcnRzIjpbeyJzdGF0dXMiOiJGSURPX0NFUlRJRkl
FRCIsImVmZmVjdGl2ZURhdGUiOiIyMDE5LTAxLTA0In0seyJzdGF0dXMiOiJGSURPX0NFUlRJRklFRF9
MMSIsImVmZmVjdGl2ZURhdGUiOiIyMDIwLTExLTE5IiwiY2VydGlmaWNhdGlvbkRlc2NyaXB0b3IiOiJ
GSURPIEFsbGlhbmNlIFNhbXBsZSBGSURPMiBBdXRoZW50aWNhdG9yIiwiY2VydGlmaWNhdGVOdW1iZXI
iOiJGSURPMjEwMDAyMDE1MTIyMTAwMSIsImNlcnRpZmljYXRpb25Qb2xpY3lWZXJzaW9uIjoiMS4wLjE
iLCJjZXJ0aWZpY2F0aW9uUmVxdWlyZW1lbnRzVmVyc2lvbiI6IjEuMC4xIn1dLCJ0aW1lT2ZMYXN0U3R
hdHVzQ2hhbmdlIjoiMjAxOS0wMS0wNCJ9XX0.MEYCIQD6RzXCuiskDXpvEtdfN4OQUQ4KxsoDLZYMTOg
Jj4B6PwIhAM3RtYg4CaGkcbFJrcJeCbAXCAC7LbfQSr8EdM79GyGw
""".replace("\n", "").encode()


AAGUID = bytes.fromhex("0132d110bf4e4208a403ab4f5f12efe5")


def test_parse_blob():
    data = parse_blob(EXAMPLE_BLOB, EXAMPLE_CA)
    assert data.no == 15
    assert len(data.entries) == 2


def test_find_by_aaguid():
    data = parse_blob(EXAMPLE_BLOB, EXAMPLE_CA)
    mds = MdsAttestationVerifier(data)
    entry = mds.find_entry_by_aaguid(AAGUID)
    assert (
        entry.metadata_statement.description
        == "FIDO Alliance Sample FIDO2 Authenticator"
    )


def test_find_by_aaguid_miss():
    data = parse_blob(EXAMPLE_BLOB, EXAMPLE_CA)
    mds = MdsAttestationVerifier(data)
    entry = mds.find_entry_by_aaguid(bytes.fromhex("0102030405060708090a0b0c0d0e0f"))
    assert entry is None


def test_find_by_chain_miss():
    data = parse_blob(EXAMPLE_BLOB, EXAMPLE_CA)
    mds = MdsAttestationVerifier(data)
    entry = mds.find_entry_by_chain([EXAMPLE_CA])
    assert entry is None


def test_filter_entries():
    data = parse_blob(EXAMPLE_BLOB, EXAMPLE_CA)
    mds = MdsAttestationVerifier(data, entry_filter=lambda e: e.aaguid != AAGUID)
    entry = mds.find_entry_by_aaguid(AAGUID)
    assert entry is None

    mds = MdsAttestationVerifier(data, entry_filter=lambda e: e.aaguid == AAGUID)
    assert mds.find_entry_by_aaguid(AAGUID)


def test_lookup_filter_does_not_affect_find_entry_by_aaguid():
    data = parse_blob(EXAMPLE_BLOB, EXAMPLE_CA)
    mds = MdsAttestationVerifier(
        data, attestation_filter=lambda e, _: e.aaguid != AAGUID
    )
    assert mds.find_entry_by_aaguid(AAGUID)
