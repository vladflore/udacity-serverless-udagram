import {APIGatewayProxyEvent, APIGatewayProxyHandler, APIGatewayProxyResult} from 'aws-lambda'
import 'source-map-support/register'
import * as AWS from 'aws-sdk'
import * as uuid from 'uuid'
import {getUserId} from "../../auth/utils";

const docClient = new AWS.DynamoDB.DocumentClient()
const groupsTable = process.env.GROUPS_TABLE || ''

export const handler: APIGatewayProxyHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    console.log('Processing event: ', event)
    const itemId = uuid.v4()

    const parsedBody = JSON.parse(event.body || '{}')
    const authorizationHeader = event.headers.Authorization || ''
    const parts = authorizationHeader.split(' ')
    const jwtToken = parts[1]

    const newItem = {
        id: itemId,
        userId: getUserId(jwtToken),
        ...parsedBody
    }

    await docClient.put({
        TableName: groupsTable,
        Item: newItem
    }).promise()

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
