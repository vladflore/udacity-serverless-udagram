import {DocumentClient} from 'aws-sdk/clients/dynamodb'
import {Group} from '../models/Group'
import AWS from 'aws-sdk'

const AWSXRay = require('aws-xray-sdk')
const XAWS = AWSXRay.captureAWS(AWS)

export class GroupAccess {

    constructor(
        private readonly docClient: DocumentClient = createDynamoDBClient(),
        private readonly groupsTable = process.env.GROUPS_TABLE || '') {
    }

    async getAllGroups(): Promise<Group[]> {
        console.log('Getting all groups')

        const result = await this.docClient.scan({
            TableName: this.groupsTable
        }).promise()

        const items = result.Items
        return items as Group[]
    }

    async createGroup(group: Group): Promise<Group> {
        await this.docClient.put({
            TableName: this.groupsTable,
            Item: group
        }).promise()

        return group
    }
}

function createDynamoDBClient() {
    if (process.env.IS_OFFLINE === 'true') {
        console.log('Creating a local DynamoDB instance')
        return new XAWS.DynamoDB.DocumentClient({
            region: 'localhost',
            endpoint: 'http://localhost:8000'
        })
    }

    return new XAWS.DynamoDB.DocumentClient()
}