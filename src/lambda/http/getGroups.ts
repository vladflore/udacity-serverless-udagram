import 'source-map-support/register'

import express from 'express';
// @ts-ignore
import * as awsServerlessExpress from 'aws-serverless-express'
import {getAllGroups} from "../../businessLogic/groups";

const app = express()

app.get('/groups', async (_req, res) => {
    const groups = await getAllGroups()
    res.header('Access-Control-Allow-Origin','*')
    res.json({
        items: groups
    })
})

const server = awsServerlessExpress.createServer(app)

// Pass API Gateway events to the Express server
exports.handler = (event: any, context: any) => {
    awsServerlessExpress.proxy(server, event, context)
}