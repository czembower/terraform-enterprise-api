'''
This lambda function handles build/destroy operations by communicating with the Terraform API
'''
import logging
import json
import infra # this is an external custom library with Vault helpers
import boto3
import os
import requests
import tempfile
from datetime import datetime

logger = logging.getLogger()
logger.setLevel(logging.INFO)

region = os.environ['AWS_REGION']
vault_role = os.environ['VAULT_ROLE']
name_key = os.environ['NAME_KEY']

# initial dynamodb
dynamodbResource = boto3.resource('dynamodb', region)
dynamodbClient   = boto3.client('dynamodb', region)

# function to write to dynamodb
def updateDeployment(deploymentUid, deployStatus):
    deploymentResource = dynamodbResource.Table('deployments-{}'.format(vault_role))
        
    key = { 
        'uid': deploymentUid
    }

    deploymentResource.update_item(
        Key = key,
        UpdateExpression = "set #status=:status, #lastUpdated=:lastUpdated, #lastUpdatedBy=:lastUpdatedBy",
        ExpressionAttributeValues = {
            ':status': deployStatus,
            ':lastUpdated': str(datetime.now()),
            ':lastUpdatedBy': 'SYSTEM'
        },
        ExpressionAttributeNames = {
            "#status": "status",
            "#lastUpdated": "lastUpdated",
            "#lastUpdatedBy": "lastUpdatedBy"
        }
    )

# create TFE configuration version
def setConfig(local_workspace_addr, auth_headers, upload_headers, configvers_payload, s3_bucket, s3_package):
    r = requests.post(local_workspace_addr + '/configuration-versions', headers=auth_headers, json=configvers_payload)
    config_id = r.json()['data']['id']
    upload_url = r.json()['data']['attributes']['upload-url']

    try:
        logger.info('Created configuration version {} with upload URL {}'.format(config_id, upload_url))
    except KeyError:
        logger.error('Error creating configuration version')
        logger.error(r.json())

    try:
        logger.info('retrieving package from s3')
        s3_client = boto3.client('s3', region)

        with tempfile.NamedTemporaryFile(mode='w+b') as t:
            s3_client.download_fileobj(s3_bucket, s3_package, t)

            logger.info('Uploading configuration data')
            with open(t.name, 'rb') as f:
                r = requests.put(upload_url, headers=upload_headers, data=f)
            if r.status_code != 200:
                logger.error(r.json())
        f.close()
        t.close()

    except Exception as e:
        logger.error('error preparing s3 object for configuration data package: {}'.format(str(e)), exc_info=True)


# create or modify TFE workspace
def setWorkspace(tfe_addr, org_workspace_addr, tfe_workspace, auth_headers, workspace_payload):
    r = requests.get(org_workspace_addr + '/' + tfe_workspace, headers=auth_headers)

    if r.status_code != 200:
        logger.info('Workspace does not exist, will create')
        r = requests.post(org_workspace_addr, headers=auth_headers, json=workspace_payload)
        workspace_id = r.json()['data']['id']
        logger.info('Created workspace with id: {}'.format(workspace_id))

    else:
        workspace_id = r.json()['data']['id']
        logger.info('Found workspace with id {} -- patching with current workspace metadata'.format(workspace_id))
        r = requests.patch(tfe_addr + '/api/v2/workspaces/' + workspace_id, headers=auth_headers, json=workspace_payload)
        logger.info(r.json())

    return workspace_id


# create or modify TFE variables
def setVars(local_workspace_addr, auth_headers, tfVars, vars_payload):
    logger.info('Checking for existing vars')
    r = requests.get(local_workspace_addr + '/vars', headers=auth_headers)
    existingVars = r.json()['data']

    for key in tfVars:
        varExists = False
        for var in existingVars:
            if var['attributes']['key'] == key:
                logger.info('var exists: {}'.format(key))
                varExists = True
                varId = var['id']
                break

        vars_payload['data']['attributes']['category'] = 'terraform'
        vars_payload['data']['attributes']['key'] = key
        vars_payload['data']['attributes']['sensitive'] = False
        if type(tfVars[key]) == list or type(tfVars[key]) == dict or type(tfVars[key]) == int or type(tfVars[key]) == bool:
            hcl = True
            vars_payload['data']['attributes']['hcl'] = True
            vars_payload['data']['attributes']['value'] = json.dumps(tfVars[key])
        else:
            hcl = False
            vars_payload['data']['attributes']['hcl'] = False
            vars_payload['data']['attributes']['value'] = tfVars[key]
        if varExists:
            vars_payload['id'] = varId
            path_url = '/vars/' + varId
            logger.info('Updating var {} (HCL: {})'.format(key, hcl))
            r = requests.patch(local_workspace_addr + path_url, headers=auth_headers, json=vars_payload)
        else:
            path_url = '/vars'
            logger.info('Creating var {} (HCL: {})'.format(key, hcl))
            r = requests.post(local_workspace_addr + path_url, headers=auth_headers, json=vars_payload)
        if r.status_code != 200:
            logger.error(r.json())

    logger.info('Setting env var for Vault token')
    vault_token = infra.get_token(vault_role)

    varExists = False
    for var in existingVars:
        if var['attributes']['key'] == 'VAULT_TOKEN':
            logger.info('var exists: {}'.format(key))
            varExists = True
            varId = var['id']
            break

    vars_payload['data']['attributes']['category'] = 'env'
    vars_payload['data']['attributes']['key'] = 'VAULT_TOKEN'
    vars_payload['data']['attributes']['sensitive'] = True
    vars_payload['data']['attributes']['hcl'] = False
    vars_payload['data']['attributes']['value'] = vault_token

    if varExists:
        vars_payload['id'] = varId
        path_url = '/vars/' + varId
        logger.info('Updating var {} (HCL: {})'.format(key, hcl))
        r = requests.patch(local_workspace_addr + path_url, headers=auth_headers, json=vars_payload)
    else:
        path_url = '/vars'
        logger.info('Creating var {} (HCL: {})'.format(key, hcl))
        r = requests.post(local_workspace_addr + path_url, headers=auth_headers, json=vars_payload)
    if r.status_code != 200:
        logger.error(r.json())


# MAIN FUNCTION
def lambda_handler(event, context):

    logger.info('event received: {}'.format(event))

    # get info and action from event payload
    try:
        deploymentUid = event['uid']
        
        if event['actionType'] == 'build':
            is_destroy = False

        elif event['actionType'] == 'destroy':
            is_destroy = True
        
        if event['action'] == 'plan':
            auto_apply = False

        elif event['action'] == 'apply':
            auto_apply = True

    except:
        raise

    try:
        # get deployment information from dynamo
        deploymentData = dynamodbClient.query(
            TableName = 'deployments-{}'.format(name_key),
            KeyConditionExpression = 'uid = :uid',
            ExpressionAttributeValues = {
                ':uid': {'S': deploymentUid}
            }
        )['Items'][0]

        # get information about associated template
        deploymentData = infra.unMarshallDdb(deploymentData)
        templateUid    = deploymentData['templateUid']

        infraTemplate = dynamodbClient.query(
            TableName = 'templates-{}'.format(name_key),
            KeyConditionExpression = 'uid = :uid',
            ExpressionAttributeValues = {
                ':uid': {'S': templateUid}
            }
        )['Items'][0]
        slot          = deploymentData['slot']
        slotData      = getSlotData(event, slot)
        infraTemplate = infra.unMarshallDdb(infraTemplate)

        metaParams = infraTemplate['metaParams']
        tfVars     = infraTemplate['components']

        # derived terraform vars
        tfVars['aws_region']          = region
        tfVars['deploy_name']         = name_key
        tfVars['slot']                = slotData['alias']
        tfVars['show_name']           = deploymentData['name']
        tfVars['size']                = slotData['size']
        tfVars['deployment_template'] = infraTemplate['name']

        tfVars['TFC_CONFIGURATION_VERSION_GIT_BRANCH'] = deploymentData['codeBranch']

    except Exception as e:
        logger.error('unable to initialize:' + str(e), exc_info=True)
        return {
            'statusCode': 500,
            'headers': { 'Content-Type': 'application/json' },
            'body': json.dumps(
                {
                    'statusType': 'serverError',
                    'statusMessage': 'function init failed'
                }
            )
        }

    else:
        logger.info('successfully initialized build')

    try:
        # configure TFE run params using dynamo content
        logger.info('processing metaParams')
        tfe_addr      = metaParams['tfeAddr']
        tfe_vers      = metaParams['tfeVer']
        tfe_org       = metaParams['tfeOrg']
        s3_bucket     = metaParams['s3bucket']
        platform      = metaParams['platform']
        s3_package    = 'builds/test1/terraform-{}-{}.tar.gz'.format(platform, deploymentData['codeBranch'])
        tfe_workspace = name_key + '-slot' + tfVars['slot'] + '-' + deploymentUid

        tfVars['TFC_WORKSPACE_NAME'] = tfe_workspace
        tfVars['deployment_uid']     = deploymentUid

        logger.info('retrieving terraform token from vault')

        # retrieve TFE team token from vault
        try:
            tfe_token = infra.get_secret(vault_role, 'admin/tokens', 'tfe-team-token')
        except:
            logger.error('unable to access terraform token')
        else:
            logger.info('successfully retrieved terraform token')

        # initialize payloads
        workspace_payload = {
            "data": {
                "attributes": {
                    "name": tfe_workspace,
                    "terraform-version": tfe_vers,
                    "auto-apply": auto_apply
                },
                "type": "workspaces"
            }
        }

        configvers_payload = {
            "data": {
                "type": "configuration-versions",
                "attributes": {
                    "auto-queue-runs": False
                }
            }
        }

        vars_payload = {
            "data": {
                "type":"vars",
                "attributes": {
                    "key":"",
                    "value":"",
                    "description":"",
                    "category":"",
                    "hcl": "",
                    "sensitive": ""
                }
            }
        }

        runtemplate_payload = {
            "data": {
                "attributes": {
                    "is-destroy": is_destroy
                },
                "type":"runs",
                "relationships": {
                    "workspace": {
                        "data": {
                            "type": "workspaces",
                            "id": ""
                        }
                    }
                }
            }
        }

        # setup http headers for auth
        auth_headers = {
            "Authorization": "Bearer {}".format(tfe_token),
            "Content-Type": "application/vnd.api+json"
        }

        upload_headers = {
            "Authorization": "Bearer {}".format(tfe_token),
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "gzip"
        }

        logger.info('initialized terraform payloads and headers -- requesting workspace details')

        # set urls
        org_workspace_addr   = tfe_addr + '/api/v2/organizations/' + tfe_org + '/workspaces'
        workspace_id         = setWorkspace(tfe_addr, org_workspace_addr, tfe_workspace, auth_headers, workspace_payload)
        local_workspace_addr = tfe_addr + '/api/v2/workspaces/' + workspace_id

        setVars(local_workspace_addr, auth_headers, tfVars, vars_payload)

        # set status integers
        if is_destroy:
            deployStatus = 8
        else:
            deployStatus = 2

        logger.info('uploading configuration and submitting plan')
        updateDeployment(deploymentUid, deployStatus)
        setConfig(local_workspace_addr, auth_headers, upload_headers, configvers_payload, s3_bucket, s3_package)

        logger.info('Starting Terraform run')
        if is_destroy:
            deployStatus = 9
        else:
            deployStatus = 13

        updateDeployment(deploymentUid, deployStatus)

        # initialize TFE run
        run_addr = tfe_addr + '/api/v2/runs'
        runtemplate_payload['data']['relationships']['workspace']['data']['id'] = workspace_id

        # execute TFE run
        r      = requests.post(run_addr, headers=auth_headers, json=runtemplate_payload)
        run_id = r.json()['data']['id']
        logger.info(r.json())

    except Exception as e:
        logger.error(str(e), exc_info=True)
        return {
            'statusCode': 500,
            'headers': { 'Content-Type': 'application/json' },
            'body': json.dumps(
                {
                    'statusType': 'serverError',
                    'statusMessage': 'function failed'
                }
            )
        }
