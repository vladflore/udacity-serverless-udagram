
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDKTCCAhGgAwIBAgIJBsazEKMJIoSRMA0GCSqGSIb3DQEBCwUAMDIxMDAuBgNV
BAMTJ3VkYWNpdHktc2VydmVybGVzcy11ZGFncmFtLmV1LmF1dGgwLmNvbTAeFw0y
MTA0MDQyMDMwMTdaFw0zNDEyMTIyMDMwMTdaMDIxMDAuBgNVBAMTJ3VkYWNpdHkt
c2VydmVybGVzcy11ZGFncmFtLmV1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAMf+4VDWrHhXKpYRZeRLajy/7/3XPPxtDvsGzl901AvE
TQmK1Oa0xr+5fJJ4yL0tsJVDArDQxdPbovd6AHHmvV/rp0foQlLo8D408LB8yZ4m
144nsHzeBpNAV/7/rfGVWfNRb8/jWXJrvtvFxwY4MMoEqkTCzZa071PmwxDNx97N
xj8g+N5gidHGx5grRndogm2hA7r80QwPZPDc9kuy5X43QRh3CzJ0gwBh2WfvhEEE
Uu37JYRhWv+8cp7QFx0hgeWIKEZI2S2nlo3o6CoAluIRqmLgQKQll9Px6mZsVLVF
XmOnd6/Go2uKQU/AeT/gyFlIXKcY6XYOhkLfEvuC18sCAwEAAaNCMEAwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUNZhFMi8syFuEmwXhcr6kEsLg0RwwDgYDVR0P
AQH/BAQDAgKEMA0GCSqGSIb3DQEBCwUAA4IBAQBVQYcyTgXFFKa4S1btzcUnGKbI
ny6MhX6UBCkR5pr7lRq1Prpy7agMSxZPnK+LCHlpqaox1K8JlwMxHbUiEXYBypdl
hCsH1qSdpCXw6KLyX/Q4II394SSNasocHpdS6A1renyvCHXRa9WIQPsVbKK17wan
xiiRdFTUUnvhhIWz8nbDbhz/jjEnww/qgkEdnnnfHqJCriBLIs39ALCPt0xXWXD4
6t4Mt4JgcyJd3VDf91CZgJcD+my6YmFiL2n2vmyYvb8i4fwZCSGYzHk1ndIggEoi
11gesxbVMb5XKizRg0YGfnoVwbT6nRLucrnk8kNKHmCFeGSyV0WXydmXzPVZ
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string | undefined): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
