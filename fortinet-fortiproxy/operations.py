""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import requests, json
from connectors.core.connector import ConnectorError, get_logger
from .constant import *

logger = get_logger('fortinet-fortiproxy')


class FortiProxy(object):
    def __init__(self, config, *args, **kwargs):
        self.apikey = config.get('api_key')
        url = config.get('server_url').strip('/')
        if not url.startswith('https://') and not url.startswith('http://'):
            self.url = 'https://{0}/api/v2/'.format(url)
        else:
            self.url = url + '/api/v2/'
        self.verify_ssl = config.get('verify_ssl')

    def make_rest_call(self, url, method, data=None, params=None):
        try:
            url = self.url + url
            params.update({'access_token': self.apikey})
            headers = {
                'Accept': 'application/json'
            }
            logger.debug("Endpoint {0}".format(url))
            response = requests.request(method, url, data=data, params=params, headers=headers, verify=self.verify_ssl)
            logger.debug("response_content {0}:{1}".format(response.status_code, response.content))
            if response.ok or response.status_code == 204:
                logger.info('Successfully got response for url {0}'.format(url))
                if 'json' in str(response.headers):
                    return response.json()
                else:
                    return response
            elif response.status_code == 404:
                return response.json()
            else:
                raise ConnectorError("{0}".format(response.content))
        except requests.exceptions.SSLError:
            raise ConnectorError('SSL certificate validation failed')
        except requests.exceptions.ConnectTimeout:
            raise ConnectorError('The request timed out while trying to connect to the server')
        except requests.exceptions.ReadTimeout:
            raise ConnectorError(
                'The server did not send any data in the allotted amount of time')
        except requests.exceptions.ConnectionError:
            raise ConnectorError('Invalid Credentials')
        except Exception as err:
            raise ConnectorError(str(err))


def check_payload(payload):
    updated_payload = {}
    for key, value in payload.items():
        if isinstance(value, dict):
            nested = check_payload(value)
            if len(nested.keys()) > 0:
                updated_payload[key] = nested
        elif value:
            updated_payload[key] = value
    return updated_payload


def create_firewall_policy(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/policy'
    query_parameter = {
        'vdom': params.pop('vdom', ''),
        'action': params.pop('action', ''),
        'nkey': params.pop('nkey', '')
    }
    policy_type = params.get('type')
    if policy_type:
        params.update({'type': Policy_Type.get(policy_type)})
    params.update({'action': params.get('action').lower()}) if params.get('action') else ''
    custom_attributes = params.pop('custom_attributes', '')
    if custom_attributes:
        params.update(custom_attributes)
    query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
    data = check_payload(params)
    response = fp.make_rest_call(endpoint, 'POST', params=query_parameter, data=json.dumps(data))
    return response


def get_firewall_policy(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/policy'
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def get_firewall_policy_details(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/policy/{0}'.format(params.pop('policyid'))
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def update_firewall_policy(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/policy/{0}'.format(params.get('policyid'))
    query_parameter = {
        'vdom': params.pop('vdom', ''),
        'action': params.pop('action', ''),
        'before': params.pop('before', ''),
        'after': params.pop('after', '')
    }
    policy_type = params.get('type')
    if policy_type:
        params.update({'type': Policy_Type.get(policy_type)})
    params.update({'action': params.get('action').lower()}) if params.get('action') else ''
    custom_attributes = params.pop('custom_attributes', '')
    if custom_attributes:
        params.update(custom_attributes)
    query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
    data = check_payload(params)
    response = fp.make_rest_call(endpoint, 'PUT', params=query_parameter, data=json.dumps(data))
    return response


def delete_firewall_policy(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/policy/{0}'.format(params.pop('policyid'))
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'DELETE', params=query_parameter)
    return response


def create_firewall_address(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/address'
    query_parameter = {
        'vdom': params.pop('vdom', ''),
        'action': params.pop('action', ''),
        'nkey': params.pop('nkey', '')
    }
    address_type = params.get('type')
    if address_type:
        params.update({'type': Address_Type.get(address_type)})
    sub_type = params.get('sub-type')
    if sub_type:
        params.update({'sub-type': Sub_Type_Address.get('sub_type')})
    custom_attributes = params.pop('custom_attributes', '')
    if custom_attributes:
        params.update(custom_attributes)
    query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
    data = check_payload(params)
    response = fp.make_rest_call(endpoint, 'POST', params=query_parameter, data=json.dumps(data))
    return response


def get_firewall_address(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/address'
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def get_firewall_address_details(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/address/{0}'.format(params.pop('name'))
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def update_firewall_address(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/address/{0}'.format(params.get('name'))
    query_parameter = {
        'vdom': params.pop('vdom', ''),
        'action': params.pop('action', ''),
        'before': params.pop('before', ''),
        'after': params.get('after', '')
    }
    address_type = params.get('type')
    if address_type:
        params.update({'type': Address_Type.get(address_type)})
    sub_type = params.get('sub-type')
    if sub_type:
        params.update({'sub-type': Sub_Type_Address.get('sub_type')})
    custom_attributes = params.pop('custom_attributes', '')
    if custom_attributes:
        params.update(custom_attributes)
    query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
    data = check_payload(params)
    response = fp.make_rest_call(endpoint, 'PUT', params=query_parameter, data=json.dumps(data))
    return response


def delete_firewall_address(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/address/{0}'.format(params.pop('name'))
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'DELETE', params=payload)
    return response


def create_firewall_address_group(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/addrgrp'
    query_parameter = {
        'vdom': params.pop('vdom', ''),
        'action': params.pop('action', ''),
        'nkey': params.pop('nkey', '')
    }
    category = params.get('category')
    if category:
        params.update({'category': Category.get('category')})
    query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
    data = check_payload(params)
    response = fp.make_rest_call(endpoint, 'POST', params=query_parameter, data=json.dumps(data))
    return response


def get_firewall_address_group(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/addrgrp'
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def get_firewall_address_group_details(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/addrgrp/{0}'.format(params.pop('name'))
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def update_firewall_address_group(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/addrgrp/{0}'.format(params.get('name'))
    query_parameter = {
        'vdom': params.pop('vdom', ''),
        'action': params.pop('action', ''),
        'before': params.pop('before', ''),
        'after': params.get('after', '')
    }
    category = params.get('category')
    if category:
        params.update({'category': Category.get('category')})
    query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
    data = check_payload(params)
    response = fp.make_rest_call(endpoint, 'PUT', params=query_parameter, data=json.dumps(data))
    return response


def delete_firewall_address_group(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall/addrgrp/{0}'.format(params.pop('name'))
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'DELETE', params=payload)
    return response


def create_firewall_service_group(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall.service/group'
    query_parameter = {
        'vdom': params.pop('vdom', ''),
        'action': params.pop('action', ''),
        'nkey': params.pop('nkey', '')
    }
    query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
    data = check_payload(params)
    response = fp.make_rest_call(endpoint, 'POST', params=query_parameter, data=json.dumps(data))
    return response


def get_firewall_service_group(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall.service/group'
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def get_firewall_service_group_details(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall.service/group/{0}'.format(params.pop('name'))
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def update_firewall_service_group(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall.service/group/{0}'.format(params.get('name'))
    query_parameter = {
        'vdom': params.pop('vdom', ''),
        'action': params.pop('action', ''),
        'before': params.pop('before', ''),
        'after': params.get('after', '')
    }
    query_parameter = {k: v for k, v in query_parameter.items() if v is not None and v != ''}
    data = check_payload(params)
    response = fp.make_rest_call(endpoint, 'PUT', params=query_parameter, data=json.dumps(data))
    return response


def delete_firewall_service_group(config, params):
    fp = FortiProxy(config)
    endpoint = 'cmdb/firewall.service/group/{0}'.format(params.pop('name'))
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'DELETE', params=payload)
    return response


def get_authenticated_firewall_users_list(config, params):
    fp = FortiProxy(config)
    endpoint = 'monitor/user/firewall'
    query_parameter = {k: v for k, v in params.items() if v is not None and v != ''}
    response = fp.make_rest_call(endpoint, 'GET', params=query_parameter)
    return response


def deauthenticate_firewall_users(config, params):
    fp = FortiProxy(config)
    endpoint = 'monitor/firewall/deauth'
    payload = check_payload(params)
    response = fp.make_rest_call(endpoint, 'POST', params={}, data=json.dumps(payload))
    return response


def get_all_banned_users_list(config, params):
    fp = FortiProxy(config)
    endpoint = 'monitor/user/banned/'
    response = fp.make_rest_call(endpoint, 'GET', params={})
    return response


def add_users_to_banned_list(config, params):
    fp = FortiProxy(config)
    endpoint = 'monitor/user/banned/add_users'
    params.update({'ip_addresses': params.get('ip_addresses').split(",")})
    payload = check_payload(params)
    response = fp.make_rest_call(endpoint, 'POST', params={}, data=json.dumps(payload))
    return response


def clear_all_banned_users_list(config, params):
    fp = FortiProxy(config)
    endpoint = 'monitor/user/banned/clear_all'
    response = fp.make_rest_call(endpoint, 'POST', params={})
    return response


def clear_banned_users_list_by_ip(config, params):
    fp = FortiProxy(config)
    endpoint = 'monitor/user/banned/clear_users'
    params.update({'ip_addresses': params.get('ip_addresses').split(",")})
    payload = check_payload(params)
    response = fp.make_rest_call(endpoint, 'POST', params={}, data=json.dumps(payload))
    return response


def _check_health(config):
    try:
        response = get_firewall_policy(config, params={})
        if response:
            return True
    except Exception as err:
        raise ConnectorError("Invalid Credentials")


operations = {
    'create_firewall_policy': create_firewall_policy,
    'get_firewall_policy': get_firewall_policy,
    'get_firewall_policy_details': get_firewall_policy_details,
    'update_firewall_policy': update_firewall_policy,
    'delete_firewall_policy': delete_firewall_policy,
    'create_firewall_address': create_firewall_address,
    'get_firewall_address': get_firewall_address,
    'get_firewall_address_details': get_firewall_address_details,
    'update_firewall_address': update_firewall_address,
    'delete_firewall_address': delete_firewall_address,
    'create_firewall_address_group': create_firewall_address_group,
    'get_firewall_address_group': get_firewall_address_group,
    'get_firewall_address_group_details': get_firewall_address_group_details,
    'update_firewall_address_group': update_firewall_address_group,
    'delete_firewall_address_group': delete_firewall_address_group,
    'create_firewall_service_group': create_firewall_service_group,
    'get_firewall_service_group': get_firewall_service_group,
    'get_firewall_service_group_details': get_firewall_service_group_details,
    'update_firewall_service_group': update_firewall_service_group,
    'delete_firewall_service_group': delete_firewall_service_group,
    'get_authenticated_firewall_users_list': get_authenticated_firewall_users_list,
    'deauthenticate_firewall_users': deauthenticate_firewall_users,
    'get_all_banned_users_list': get_all_banned_users_list,
    'add_users_to_banned_list': add_users_to_banned_list,
    'clear_all_banned_users_list': clear_all_banned_users_list,
    'clear_banned_users_list_by_ip': clear_banned_users_list_by_ip
}
