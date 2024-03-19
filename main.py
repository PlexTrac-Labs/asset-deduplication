import yaml
from copy import deepcopy
import time

import settings
import utils.log_handler as logger
log = logger.log
from utils.auth_handler import Auth
import utils.input_utils as input
import utils.general_utils as utils
import api
from utils.log_handler import IterationMetrics


def get_page_of_clients(page: int = 0, clients: list = [], total_clients: int = -1) -> None:
    """
    Handles traversing pagination results to create a list of all items.

    :param page: page to start on, for all results use 0, defaults to 0
    :type page: int, optional
    :param clients: the list passed in will be added to, acts as return, defaults to []
    :type clients: list, optional
    :param total_clients: used for recursion to know when all pages have been gathered, defaults to -1
    :type total_clients: int, optional
    """
    payload = {
        "pagination": {
            "offset": page*100,
            "limit": 100
        }
    }
    # region - full structure of client data response

    # only need a list of client IDs

    # {
    #     "status": "success",
    #     "data": [
    #         {
    #             "client_id": 4155,
    #             "name": "Test Client",
    #             "poc": "poc name",
    #             "tags": [
    #                 "test"
    #             ]
    #         }
    #     ],
    #     "meta": {
    #         "pagination": {
    #             "offset": 0,
    #             "limit": 25,
    #             "total": 2
    #         }
    #     }
    # }
    # endregion
    response = api.clients.list_clients(auth.base_url, auth.get_auth_headers(), payload)
    if response.json.get("status") != "success":
        log.critical(f'Could not retrieve clients from instance. Exiting...')
        exit()
    total_clients = int(response.json['meta']['pagination']['total'])
    if len(response.json['data']) > 0:
        clients += deepcopy(response.json['data'])

    if len(clients) < total_clients:
        return get_page_of_clients(page+1, clients, total_clients)
    
    return None

def get_client_choice(clients) -> int:
    """
    Prompts the user to select from a list of clients to export related assets to CSV.
    Based on subsequently called functions, this will return a valid option or exit the script.

    :param repos: List of clients returned from the POST List Clients endpoint
    :type repos: list[client objects]
    :return: 0-based index of selected client from the list provided
    :rtype: int
    """
    log.info(f'List of Clients:')
    index = 1
    for client in clients:
        log.info(f'{index} - Name: {client["name"]} | ID: {client["client_id"]} | Tags: {client.get("tags", [])}')
        index += 1
    return input.user_list("Select a client to export assets from", "Invalid choice", len(clients)) - 1

def get_client_assets(client) -> list | None:
    """
    Gets a list of client assets related to the passed in client.

    :param client: client object to get related asset of
    :type client: client object from GET /api/v1/client/list endpoint
    :return: the list of asset objects from GET /api/v1/client/{clientId}/assets endpoint - OR - None, if any errors prevented getting client asset list
    :rtype: list[asset objects] | None
    """
    client_id = client.get("client_id")
    if client_id == None:
        log.exception(f'get_client_asset exception: client object does not have id')
        return None
    try:
        # region - full structure of asset response

        # same shape as sent to the PUT update finding request when adding an existing asset
        # asset response has same shape as v1 GET Get Asset response

        # [
        #    {
        #        "asset": "150.40.20.24",
        #        "child_assets": {},
        #        "client_id": 1045,
        #        "created": "Tue Jan 20 1970 13:33:04 GMT+0000",
        #        "createdAt": 1690384996,
        #        "doc_type": "client_asset",
        #        "findings": {
        #            "34460": {
        #                "id": "34460",
        #                "client_id": 1045,
        #                "createdAt": 1701728379267,
        #                "updatedAt": 1701728379267,
        #                "title": "Unsupported Web Server Detection",
        #                "severity": "High",
        #                "status": "Open",
        #                "assignedTo": null,
        #                "instances": {
        #                    "565941470": {
        #                        "report_id": 565941470,
        #                        "report_flaw_title": "Unsupported Web Server Detection",
        #                        "report_severity": "High",
        #                        "report_status": "Open",
        #                        "report_flaw_visibility": "draft",
        #                        "createdAt": 1701728379267,
        #                        "updatedAt": 1701728379267
        #                    }
        #                },
        #                "ports": {},
        #                "vulnerableParameters": [],
        #                "notes": [],
        #                "evidence": []
        #            }
        #        },
        #        "id": "0049e8bd-9053-43ce-917a-d6d271ea2956",
        #        "parent_asset": null,
        #        "updatedAt": 1701728379719,
        #        "assetCriticality": "",
        #        "description": "",
        #        "dns_name": "",
        #        "host_fqdn": "",
        #        "host_rdns": "",
        #        "hostname": "",
        #        "knownIps": [
        #        ],
        #        "mac_address": "",
        #        "netbios_name": "",
        #        "notes": [],
        #        "operating_system": "Unix",
        #        "pci_status": "",
        #        "physical_location": "",
        #        "ports": {
        #            "4786": {
        #                "last_seen": 1690384996832,
        #                "number": "4786",
        #                "script": "",
        #                "service": "",
        #                "protocol": "tcp",
        #                "version": ""
        #            }
        #        },
        #        "tags": [],
        #        "total_cves": 0,
        #        "type": "General"
        #    },
        #
        #    ...
        # ]
        # endregion
        response = api.assets.list_client_assets(auth.base_url, auth.get_auth_headers(), client_id)
        if response.has_json_response and type(response.json) is list:
            return response.json
    except Exception as e:
        log.debug(f'get_client_assets exception: {e}')
        return None


def get_asset_ip_list(asset) -> list:
    """
    Given an asset, looks for all related IP address. First at the asset name field to try and determine if this field contains an IP. If not, looks at the knownIps field.

    :param asset: asset to get the IP from
    :type asset: asset object from GET /api/v1/client/{clientId}/assets endpoint
    :return: list of IP addresses relating to the given asset, returns empty list if there was no IP value found in the asset name or knownIps list
    :rtype: list
    """
    asset_ip_list = []
    asset_name = asset.get("asset")
    asset_known_ips = asset.get("knownIps", [])

    if utils.is_valid_ipv4_address(asset_name):
        asset_ip_list.append(asset_name)
    if len(asset_known_ips) > 0:
        asset_ip_list += asset_known_ips
    return asset_ip_list
    
def get_asset_name(asset) -> str | None:
    name = ""
    asset_name = asset.get("asset")

    if not utils.is_valid_ipv4_address(asset_name):
        name = asset_name
        return name
    else:
        return None

def get_asset_hostname(asset) -> str | None:
    hostname = ""
    asset_hostname = asset.get("hostname", "")

    if asset_hostname != "" and not utils.is_valid_ipv4_address(asset_hostname):
        hostname = asset_hostname
        return hostname
    else:
        return None

def is_matching_asset(asset_a, asset_b) -> bool:
    asset_a_ip_list = get_asset_ip_list(asset_a)
    asset_b_ip_list = get_asset_ip_list(asset_b)
    asset_a_name = get_asset_name(asset_a)
    asset_b_name = get_asset_name(asset_b)
    asset_a_hostname = get_asset_hostname(asset_a)
    asset_b_hostname = get_asset_hostname(asset_b)

    if asset_a_name != None:
        if asset_a_name == asset_b_name or asset_a_name == asset_b_hostname:
            return True
    elif asset_b_name != None:
        if asset_b_name == asset_a_name or asset_b_name == asset_a_hostname:
            return True
    elif asset_a_hostname != None:
        if asset_a_hostname == asset_b_hostname or asset_a_hostname == asset_b_name:
            return True
    elif asset_b_hostname != None:
        if asset_b_hostname == asset_a_hostname or asset_b_hostname == asset_a_name:
            return True
    for ip in asset_a_ip_list:
        if ip in asset_b_ip_list:
            return True
        
    return False

def does_asset_match_group(new_asset, group) -> bool:
    for asset in group:
        if is_matching_asset(new_asset, asset):
            return True
        
    return False

def get_main_asset_from_group(group: list) -> dict:
    """
    Pickes an asset from a duplication group to be the main asset that all others get merged into.

    :param group: list of assets from a duplication group
    :type group: list
    :return: the asset that should be the main asset
    :rtype: dict
    """
    # In Plextrac you can't have 2 client assets with the same name. So it matters which asset in each group of dulicates becomes the main asset.
    # If you pick an asset with an IP for the name, that asset's name will likely get changed to the name of another asset in it's duplication group.
    # This would cause any client asset update request to fail, since another client asset in Plextrac already has that asset name.
    asset_group_names = [get_asset_name(x) for x in group]
    for i, name in enumerate(asset_group_names):
        if name != None:
            return group[i]
    return group[0]


def combine_and_merge_asset_data(main_asset, dup_asset) -> bool:
    single_fields = ["parent_asset", "type", "assetCriticality", "system_owner", "data_owner", "dns_name", "host_fqdn", "host_rdns", "mac_address", "physical_location", "netbios_name", "total_cves", "pci_status", "description"]
    list_fields = ["operating_system", "tags"]
    dict_fields = ["ports", "child_assets"]
    asset_main_ip_list = get_asset_ip_list(main_asset)
    asset_dup_ip_list = get_asset_ip_list(dup_asset)
    asset_main_name = get_asset_name(main_asset)
    asset_dup_name = get_asset_name(dup_asset)
    asset_main_hostname = get_asset_hostname(main_asset)
    asset_dup_hostname = get_asset_hostname(dup_asset)

    # determine if asset can be automatically merged - see example in project summary doc for manual deduplication need
    if asset_main_name != None and asset_dup_name != None and asset_main_name.lower() != asset_dup_name.lower():
        log.exception(f'Both assets have a non IP name that don\'t match, manual deduplication required: Asset 1: \'{asset_main_name}\' | Asset 2: \'{asset_dup_name}\'')
        return False

    # determine new asset name when merging (asset name, hostname)
    if asset_main_name != None:
        main_asset['asset'] = asset_main_name
    elif asset_dup_name != None:
        main_asset['asset'] = asset_dup_name
    elif asset_main_hostname != None:
        main_asset['asset'] = asset_main_hostname
        main_asset['hostname'] = asset_main_hostname
    elif asset_dup_hostname != None:
        main_asset['asset'] = asset_dup_hostname
        main_asset['hostname'] = asset_dup_hostname
    elif len(asset_main_ip_list) > 0:
        main_asset['asset'] = asset_main_ip_list[0]
    elif len(asset_dup_ip_list) > 0:
        main_asset['asset'] = asset_dup_ip_list[0]
    else: # it should not be possible to run in this condition
        main_asset['asset'] = main_asset['id']

    # handling IPs separate from other list fields since the knwonIps list might have gotten an additional value it an asset name was an IP value
    for ip in asset_dup_ip_list:
        if ip not in asset_main_ip_list:
            asset_main_ip_list.append(ip)
    main_asset['knownIps'] = list(set(asset_main_ip_list))

    # combine single value fields
    for field in single_fields:
        if main_asset.get(field) == None or main_asset.get(field) == "":
            if dup_asset.get(field) != None and dup_asset.get(field) != "":
                main_asset[field] = dup_asset[field]
    # combine list value fields
    for field in list_fields:
        if main_asset.get(field) == None:
            main_asset[field] = []
    for field in list_fields:
        for value in dup_asset.get(field, []):
            if value not in main_asset.get(field):
                main_asset[field].append(value)
    # handle dict value fields
    for field in dict_fields:
        for key, value in dup_asset.get(field).items():
            if key not in main_asset.get(field).keys():
                main_asset[field][key] = value
    
    return True


def get_finding_ref(client_id, report_id, finding_id, finding_refs:list) -> dict | None:
    matching_refs = list(filter(lambda x: x['client_id']==client_id and x['report_id']==report_id and x['finding_id']==finding_id, finding_refs))
    if len(matching_refs) == 1:
        return matching_refs[0]
    elif len(matching_refs) > 1:
        # if this error triggers on execution, there is a fundamental flaw in the script logic that needs to be determined and fixed
        log.critical(f'Script encountered an unexpected condition; please debug for potential logic errors: Multiple finding references were created for a single finding')
        return None
    else:
        return None
    
def create_finding_ref(client_id, report_id, finding_id, finding_refs:list) -> dict:
    finding_ref = {
        "client_id": client_id,
        "report_id": report_id,
        "finding_id": finding_id,
        "updates": [],
        "finding": None
    }
    finding_refs.append(finding_ref)
    return finding_ref


def update_finding_asset_reference(finding, dup_asset, main_asset) -> bool:
    """
    Takes a finding object from the Get Finding response and replaces the duplicate affected asset data with the main client asset.

    :param finding: finding that has the dup asset as an affected asset that needs to be replaced
    :type finding: finding object from the Get Finding response
    :param dup_asset: dup asset that needs to be replaced
    :type dup_asset: client asset object from the List Client Assets response
    :param main_asset: main asset to replace dup asset
    :type main_asset: client asset object from the List Client Assets response
    :return: whether the replace operation was successful
    :rtype: bool
    """
    # checking we have the asset sections of the finding payload that need to be updated
    dup_asset_id = dup_asset.get("id")
    if dup_asset_id == None:
        # should not be possible to reach this condition
        log.critical(f'Plextrac data corruption: dup asset does not have ID property')
        return False
    main_asset_id = main_asset.get("id")
    if main_asset_id == None:
        # should not be possible to reach this condition
        log.critical(f'Plextrac data corruption: main asset does not have ID property')
        return False
    finding_main_asset_data = finding.get("affected_assets", {}).get(main_asset['id'])
    finding_dup_asset_data = finding.get("affected_assets", {}).get(dup_asset['id'])
    if finding_dup_asset_data == None:
        # should not be possible to reach this condition
        log.critical(f'Script encountered an unexpected condition; please debug for potential logic errors: finding doesn\'t have affected asset info with matching dup asset ID')
        return False
    
    # update finding payload

    # NOTES
    # The finding PUT request only processes some info on the payload. Info about the affected asset properties shown on
    # the edit affected asset screen ARE proecssed. Info about the client asset, not shown when editing an existing
    # affected asset are not processed, since this data is stored on the client asset doc.

    # handle IF finding already contains relations to both the main and dup asset    
    if finding_main_asset_data != None:
        # need to add affect asset fields (ports, locationUrl, vuln params, notes, evidence) from dup to main asset
        if len(finding_dup_asset_data.get("ports", [])) > 0: 
            finding_main_asset_data['ports'].update(finding_dup_asset_data['ports'])
        if len(finding_dup_asset_data.get("vulnerableParameters", [])) > 0: 
            finding_main_asset_data['vulnerableParameters'] += finding_dup_asset_data['vulnerableParameters']
        if len(finding_dup_asset_data.get("evidence", [])) > 0: 
            finding_main_asset_data['evidence'] += finding_dup_asset_data['evidence']

        if finding_dup_asset_data.get("locationUrl") != None:
            if finding_main_asset_data.get("locationUrl") == None:
                finding_main_asset_data['locationUrl'] = finding_dup_asset_data['locationUrl']
        if finding_dup_asset_data.get("notes", "") != "":
            if finding_main_asset_data.get("notes", "") == "":
                finding_main_asset_data['notes'] = finding_dup_asset_data['notes']
        # remove old dup asset data from findings affected assets
        finding['affected_assets'].pop(dup_asset_id)
        return True
    # ELSE finding only contain the dup asset
    else:
        # update the dup asset data with the main asset ID
        finding_dup_asset_data['id'] = main_asset_id
        # - add dup asset data (updated ID to "represent" main asset) to findings affected assets
        # - this operation will make Plextrac associate all the pre-existing main asset properties, with this dup affected asset object,
        #   that doesn't have all the asset details populated
        # - we're not explicitly combining the client asset properties from each asset here (this was done earlier)
        # - we're taking advantage of some asset syncing functionality in Plextrac, where, on a finding update, Plextrac checks each affected
        #   asset on a finding, and makes sure it has the same properties as any existing client assets (the existing asset we already combined data on)
        finding['affected_assets'][main_asset_id] = finding_dup_asset_data
        # remove old dup asset data from findings affected assets
        finding['affected_assets'].pop(dup_asset_id)
        return True


def delete_client_asset(asset) -> bool:
    """
    Tries to delete a given asset. Logs errors

    :param asset: asset to be deleted
    :type asset: asset object from GET /api/v1/client/{clientId}/assets endpoint
    :return: whether the delete operation was successful
    :rtype: bool
    """
    log.info(f'Deleting asset \'{asset.get("asset", "missing asset name")}\'')
    try:
        response = api.assets.delete_asset(auth.base_url, auth.get_auth_headers(), asset['client_id'], asset['id'])
        log.success(f'Deleted asset')
        return True
    except Exception as e:
        log.exception(f'Could not delete asset \'{asset.get("asset", "missing asset name")}\'. Skipping...\n{e}')
        return False



if __name__ == '__main__':
    for i in settings.script_info:
        print(i)

    with open("config.yaml", 'r') as f:
        args = yaml.safe_load(f)

    auth = Auth(args)
    auth.handle_authentication()


    ### error tracking throughtout script
    # duplicate assets that failed at some point in the script
    failed_assets_on_merge_and_update_assets = {}
    failed_assets_on_update_findings = {}

    ### get list of clients in instance
    log.info(f'Loading clients from instance...')
    time.sleep(1)
    clients = []
    get_page_of_clients(clients=clients)
    log.success(f'Loaded {len(clients)} client(s) from instance')


    ### prompt user to select a client in which to dedup assets
    while True:
        choice = get_client_choice(clients)
        if input.continue_anyways(f'Run script to deduplicate assets for \'{clients[choice]["name"]}\'?'):
            break
    client = clients[choice]
    log.info(f'\n\nProcessing client \'{client.get("name", "missing client name")}\'...')


    ### load client assets
    log.info(f'Loading assets from client...')
    time.sleep(3)
    client_assets = get_client_assets(client)
    if client_assets == None or len(client_assets) < 1:
        log.exception(f'Client has no assets or could not get assets for client. Exiting...')
        exit()
    log.success(f'Loaded {len(client_assets)} asset(s) from client.')


    ### filter client_assets into a multileveled list of related assets
    log.info(f'Finding duplicate assets...')
    time.sleep(3)
    asset_relations = []
    for new_asset in client_assets:
        matched = False
        for unique_asset_group in asset_relations:
            if does_asset_match_group(new_asset, unique_asset_group):
                unique_asset_group.append(new_asset)
                matched = True
                break # shouldn't need a break since no other matches should be made
        if matched == False:
            asset_relations.append([new_asset])
    # I'm not sure if it's possible to run into a corner case here. It might be possible where asset_relations can end up containing 2 separete groups that are related.
    # Possibly due to order of assets when processed. If this case is possible, the following section will merge these groups together
    potential_matching_groups = True
    while potential_matching_groups:
        for i, unique_asset_group in enumerate(asset_relations):
            found_match = False
            for j, group in enumerate(asset_relations[i+1:], i+1):
                matching_groups = False
                for asset in group:
                    if does_asset_match_group(asset, unique_asset_group):
                        matching_groups = True
                        break                        
                if matching_groups:
                    # combine groups
                    for asset in group:
                        unique_asset_group.append(asset)
                    asset_relations.pop(j)
                    found_match = True
                    break
            if found_match:
                break
            elif found_match == False and i == len(asset_relations)-1:
                potential_matching_groups = False
    # continue script with only duplicate groups
    asset_relations_dup_groups = [x for x in asset_relations if len(x)>1]
    log.success(f'Found {len(asset_relations_dup_groups)} group(s) of 1 or more duplicate assets')


    ### update clients assets
    # region
    # update main client asset per group with the combination of data from all assest in the group
    log.info(f'Combining duplicate assets and updating main client asset in Plextrac...')
    time.sleep(3)
    failed_asset_group_updates = []
    asset_update_metrics = IterationMetrics(len(asset_relations_dup_groups))
    for i, unique_asset_group in enumerate(asset_relations_dup_groups):
        main_asset = get_main_asset_from_group(unique_asset_group)
        main_asset_og_name = main_asset['asset']
        duplicate_assets = [i for i in unique_asset_group if i['id'] != main_asset['id']]
        # if there are no dup assets in this group continue - no need to send the update request for the single main asset
        if len(duplicate_assets) < 1:
            continue
        # combine each related asset
        failed_asset_merges_in_group = []
        for duplicate_asset in duplicate_assets:
            if not combine_and_merge_asset_data(main_asset, duplicate_asset):
                log.exception(f'Could not combine \'{duplicate_asset["asset"]}\' into \'{main_asset_og_name}\'. Skipping \'{duplicate_asset["asset"]}\'... (Any previously logged asset name changes not updated in Plextrac!)')
                failed_asset_merges_in_group.append(duplicate_asset)
                continue
            # keep track of original asset name after potential changes
            if main_asset_og_name != main_asset['asset']:
                log.info(f'Asset \'{main_asset_og_name}\' renamed to \'{main_asset["asset"]}\' while merging \'{duplicate_asset["asset"]}\' into \'{main_asset_og_name}\' (Update has not been made in Plextrac yet!)')
                main_asset_og_name = main_asset['asset']
        # track which assets were success to be used in logging
        unique_asset_group_merge_successes = deepcopy(unique_asset_group)
        # remove dup assets from group that weren't successfully merged into main asset
        if len(failed_asset_merges_in_group) > 0:
            # add failed asset into error tracking throughtout script
            for failed_dup_asset in failed_asset_merges_in_group:
                unique_asset_group_merge_successes = list(filter(lambda x: x['id'] != failed_dup_asset['id'], unique_asset_group_merge_successes))
                failed_assets_on_merge_and_update_assets[failed_dup_asset['id']] = failed_dup_asset

        # update client asset request in PT
        try:
            response = api.assets.update_asset(auth.base_url, auth.get_auth_headers(), main_asset['client_id'], main_asset['id'], main_asset)
            if not response.has_json_response and response.json.get("message") == "success":
                log.exception(f'Update asset request did not return success message. Skipping group of related assets... (Any previously logged asset name changes not updated in Plextrac!)')
                failed_asset_group_updates.append(i)
                log.info(asset_update_metrics.print_iter_metrics())
                continue
            log.success(f'Updated asset in Plextrac \'{main_asset["asset"]}\' with data from {len(unique_asset_group_merge_successes)-1} related assets: {list(filter(lambda x:x != main_asset["asset"], list(map(lambda x: x["asset"], unique_asset_group_merge_successes))))}')
            log.info(asset_update_metrics.print_iter_metrics())
        except Exception as e:
            log.exception(f'Could not update asset. Skipping group of related assets... (Any previously logged asset name changes not updated in Plextrac!)')
            failed_asset_group_updates.append(i)
            log.info(asset_update_metrics.print_iter_metrics())
            continue
    # removing all groups whose main asset was not successfully updated
    for i in failed_asset_group_updates[::-1]:
        for failed_dup_asset in asset_relations_dup_groups[i]:
            failed_assets_on_merge_and_update_assets[failed_dup_asset['id']] = failed_dup_asset
        asset_relations_dup_groups.pop(i)
    if len(failed_assets_on_merge_and_update_assets) > 1:
        log.exception(f'Failed to merge {len(failed_assets_on_merge_and_update_assets)} asset(s). These asset(s) will be excluded when determining duplicate asset replacements')
    # endregion

    
    ### filter asset_relations_dup_groups into list of asset pair deduplications that need to be made. needed for finding updates
    log.info(f'Determining asset pair replacements needed to update finding records...')
    time.sleep(3)
    asset_replacements = []
    for unique_asset_group in asset_relations_dup_groups:
        main_asset = get_main_asset_from_group(unique_asset_group)
        duplicate_assets = [x for x in unique_asset_group if x['id'] != main_asset['id']]
        for duplicate_asset in duplicate_assets:
            if duplicate_asset['id'] not in failed_assets_on_merge_and_update_assets.keys():
                asset_replacements.append([main_asset, duplicate_asset])
    
    log.success(f'Found {len(asset_replacements)} asset replacements needed to update all findings associated with duplicate assets.')


    ### update affected assets on finding records
    
    # to make the script more efficient, we first find all changes that need to be made accross all findings. this potentially includes multiple
    # replacements for a single finding.
    # this allows each finding to be updated once to decrease total amount of API calls and consequent script execution time
    finding_refs = []

    ## SECTION 1 - parse all necessary finding updates based on loaded assets
    # region
    log.info(f'Determining replacements needed on each finding...')
    time.sleep(3)
    # loop on asset pair replacements that need to be made
    parsing_metrics = IterationMetrics(len(asset_replacements))
    for replacement in asset_replacements:
        duplicate_asset = replacement[1]
        main_asset = replacement[0]
        log.info(f'Replacement: \'{duplicate_asset["asset"]}\' -> \'{main_asset["asset"]}\'')

        log.info(f'Getting finding asset references that need to be updated...')
        # get list of associated findings for, a single asset needing to be replaced
        # NOTE: Same Finding on Multiple Reports
        # the client asset only references 1 finding that is associated across all report
        # this means is 2 findings, having the same name, exist on 2 different reports, the asset will only
        # hold the "finding object" for one of those 2 findings
        #
        # since a finding will have the same flaw_id if it exists with the same title in multiple reports,
        # this list won't contain all references of report findings that need to be updated
        associated_finding_references = list(duplicate_asset.get("findings", {}).values())

        # loop on findings that need to be fixed for, a single asset needing to be replaced
        for finding_reference in associated_finding_references:
            # get all references from asset > findings > instances/reports
            # see NOTE: Same Finding on Multiple Reports
            report_ids = list(finding_reference.get("instances", {}).keys())
            client_id = finding_reference.get("client_id")
            finding_id = finding_reference.get("id")

            # loop on report(s) where the finding exists
            # this solves NOTE: Same Finding on Multiple Reports
            for report_id in report_ids:
                log.info(f'Processing finding \'{finding_reference.get("title", "missing finding title")}\' in report \'{report_id}\'')

                finding_ref = get_finding_ref(client_id, report_id, finding_id, finding_refs)
                if finding_ref == None:
                    finding_ref = create_finding_ref(client_id, report_id, finding_id, finding_refs)

                update = {
                    "duplicate_asset": duplicate_asset,
                    "main_asset": main_asset
                }
                finding_ref['updates'].append(update)

        log.info(parsing_metrics.print_iter_metrics())
    log.success(f'Found {len(finding_refs)} findings that have affected assets that need to be updated')
    # endregion SECTION 1
        
    
    ## SECTION 2 - apply combined updates to each associated finding
    # region
    log.info(f'Updating each applicable associated finding in Plextrac with all discovered asset replacements...')
    time.sleep(3)

    # loop on each finding across all reports of the client that need asset references updated
    update_metrics = IterationMetrics(len(finding_refs))
    for finding_ref in finding_refs:

        # get finding in question
        log.info(f'GETing finding for IDs: client:{finding_ref["client_id"]} - report:{finding_ref["report_id"]} - finding:{finding_ref["finding_id"]}')
        try:
            response = api.findings.get_finding(auth.base_url, auth.get_auth_headers(), finding_ref["client_id"], finding_ref["report_id"], finding_ref["finding_id"])
            if not response.has_json_response:
                log.exception(f'Finding \'{finding_ref["finding_id"]}\' in report \'{finding_ref["report_id"]}\' doesn\'t have proper JSON response. Cannot update this finding. Skipping...')
                # add affected dup assets to non updated list
                for update in finding_ref['updates']:
                    failed_assets_on_update_findings[update['duplicate_asset']['id']] = update['duplicate_asset']
                log.info(update_metrics.print_iter_metrics())
                continue
            finding_ref['finding'] = response.json
            log.success(f'Loaded finding \'{finding_ref["finding"].get("title", "missing finding title")}\' from instance')
        except Exception as e:
            log.exception(f'Could not GET finding: {e}')
            # add affected dup assets to non updated list
            for update in finding_ref['updates']:
                failed_assets_on_update_findings[update['duplicate_asset']['id']] = update['duplicate_asset']
            log.info(update_metrics.print_iter_metrics())
            continue

        # process all asset updates on finding objects from Get Finding endpoint
        log.info(f'Processing finding record and making asset replacements...')
        for update in finding_ref['updates']:
            if not update_finding_asset_reference(finding_ref['finding'], update['duplicate_asset'], update['main_asset']):
                failed_assets_on_update_findings[update['duplicate_asset']['id']] = update['duplicate_asset']
        
        # update finding
        log.info(f'PUTing finding in Plextrac with all updated asset replacements...')
        try:
            response = api.findings.update_finding(auth.base_url, auth.get_auth_headers(), finding_ref['client_id'], finding_ref['report_id'], finding_ref['finding_id'], finding_ref['finding'])
            if not (response.has_json_response and response.json.get("message") == "success"):
                log.exception(f'Finding \'{finding_ref["finding_id"]}\' in report \'{finding_ref["report_id"]}\' PUT request did not return success message. Cannot apply updates to this finding. Skipping...')
                # add affected dup assets to non updated list
                for update in finding_ref['updates']:
                    failed_assets_on_update_findings[update['duplicate_asset']['id']] = update['duplicate_asset']
                log.info(update_metrics.print_iter_metrics())
                continue
            log.success(f'Updated finding')
        except Exception as e:
            log.exception(f'Could not PUT finding with updated asset info: {e}')
            # add affected dup assets to non updated list
            for update in finding_ref['updates']:
                failed_assets_on_update_findings[update['duplicate_asset']['id']] = update['duplicate_asset']
            log.info(update_metrics.print_iter_metrics())
            continue

        log.info(update_metrics.print_iter_metrics())
    log.success(f'Findings updated with asset replacements')
    if len(failed_assets_on_update_findings) > 0:
        log.exception(f'During finding updates, could not make {len(failed_assets_on_update_findings)} replacements. Failed replacements will be accounted for later and logged')
    # endregion SECTION 2
        

    ##  SECTION 3 - delete dup client asset that are no longer tied to any findings
    # region
    log.info(f'Removing duplicate client assets that were sucessfully replaced...')
    time.sleep(3)

    # loop on assets that need to be deleted
    delete_metrics = IterationMetrics(len(asset_replacements))
    for asset_replacement_pair in asset_replacements:
        duplicate_asset = asset_replacement_pair[1]
        log.info(f'Processing asset \'{duplicate_asset.get("asset", "missing asset name")}\' for deletion...')

        if duplicate_asset['id'] in list(failed_assets_on_update_findings.keys()):
            log.info(delete_metrics.print_iter_metrics())
            continue
        
        delete_client_asset(duplicate_asset)
        log.info(delete_metrics.print_iter_metrics())
    # endregion SECTION 3


    ### script completed logging
    num_success = len(asset_replacements) - len(failed_assets_on_update_findings)
    log.success(f'\n\nUpdated {num_success}/{len(asset_replacements)} found asset replacements in \'{client.get("name", "missing client name")}\'')
    # after replacements were determined this list shows failed replacements
    if num_success < len(asset_replacements):
        log.exception(f'List of duplicate assets that could not be fully replaced. See entire script execution log for details')
        for asset_id, asset_data in failed_assets_on_update_findings.items():
            log.exception(asset_data['asset'])
    # shows assets which failed to create replacements
    if len(failed_assets_on_merge_and_update_assets) > 0:
        log.exception(f'Failed to merge or update assets for {len(failed_assets_on_merge_and_update_assets)} duplicate assets')
        for asset_id, asset_data in failed_assets_on_merge_and_update_assets.items():
            log.exception(asset_data['asset'])
