import {CustomAuthorizerEvent, CustomAuthorizerHandler, CustomAuthorizerResult} from 'aws-lambda'

import {verify} from 'jsonwebtoken'
import {JwtToken} from "../../auth/JwtToken";

const auth0Secret = process.env.AUTH_0_SECRET || ''

export const handler: CustomAuthorizerHandler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {

    try {
        const decodedToken = verifyToken(event.authorizationToken)
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

    function verifyToken(authorizationHeader: string | undefined): JwtToken {
        if (!authorizationHeader) {
            throw new Error('No authorization header')
        }
        if (!authorizationHeader.toLocaleLowerCase().startsWith('bearer')) {
            throw new Error('Invalid authorization header')
        }
        const parts = authorizationHeader.split(' ')
        const token = parts[1]

        return verify(token, auth0Secret) as JwtToken
    }

}