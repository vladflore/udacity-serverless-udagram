import {CustomAuthorizerEvent, CustomAuthorizerResult} from 'aws-lambda'

import {verify} from 'jsonwebtoken'
import {JwtToken} from "../../auth/JwtToken";
import middy from '@middy/core'
import secretsManager from '@middy/secrets-manager'

const secretId = process.env.AUTH_0_SECRET_ID || ''
const secretField = process.env.AUTH_0_SECRET_FIELD || ''

export const handler = middy(async (event: CustomAuthorizerEvent, context): Promise<CustomAuthorizerResult> => {

    try {
        // @ts-ignore
        const decodedToken = verifyToken(event.authorizationToken, context.AUTH0_SECRET[secretField])
        console.log('User was authorized')
        return {
            principalId: decodedToken.sub,
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
        console.log('User was not authorized', e.message);
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
})

function verifyToken(authorizationHeader: string | undefined, secret: string): JwtToken {
    if (!authorizationHeader) {
        throw new Error('No authorization header')
    }
    if (!authorizationHeader.toLocaleLowerCase().startsWith('bearer')) {
        throw new Error('Invalid authorization header')
    }
    const parts = authorizationHeader.split(' ')
    const token = parts[1]

    return verify(token, secret) as JwtToken
}

handler.use(secretsManager({
    setToContext: true,
    cacheExpiry: 60000,
    fetchData: {
        AUTH0_SECRET: secretId
    }
}))