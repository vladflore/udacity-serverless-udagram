import {APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult} from 'aws-lambda'
import 'source-map-support/register'
import {createGroup} from "../../businessLogic/groups";

export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    console.log('Processing event: ', event)

    const parsedBody = JSON.parse(event.body || '{}')
    const authorizationHeader = event.headers.Authorization || ''
    const parts = authorizationHeader.split(' ')
    const jwtToken = parts[1]

    const newItem = await createGroup(parsedBody, jwtToken)

    return {
        statusCode: 201,
        headers: {
            'Access-Control-Allow-Origin': '*'
        },
        body: JSON.stringify({
            newItem
        })
    }
}
