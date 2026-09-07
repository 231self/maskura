# CreateMcpTokenRequest


## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**expires_in** | **int** |  | [optional] 
**label** | **str** |  | 

## Example

```python
from maskura_client.models.create_mcp_token_request import CreateMcpTokenRequest

# TODO update the JSON string below
json = "{}"
# create an instance of CreateMcpTokenRequest from a JSON string
create_mcp_token_request_instance = CreateMcpTokenRequest.from_json(json)
# print the JSON string representation of the object
print(CreateMcpTokenRequest.to_json())

# convert the object into a dict
create_mcp_token_request_dict = create_mcp_token_request_instance.to_dict()
# create an instance of CreateMcpTokenRequest from a dict
create_mcp_token_request_from_dict = CreateMcpTokenRequest.from_dict(create_mcp_token_request_dict)
```
[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


