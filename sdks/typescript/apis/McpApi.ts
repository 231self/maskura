// TODO: better import syntax?
import {BaseAPIRequestFactory, RequiredError, COLLECTION_FORMATS} from './baseapi';
import {Configuration} from '../configuration';
import {RequestContext, HttpMethod, ResponseContext, HttpFile, HttpInfo} from '../http/http';
import {ObjectSerializer} from '../models/ObjectSerializer';
import {ApiException} from './exception';
import {canConsumeForm, isCodeInRange} from '../util';
import {SecurityAuthentication} from '../auth/auth';


import { CreateMcpTokenRequest } from '../models/CreateMcpTokenRequest';
import { DeleteMcpTokenRequest } from '../models/DeleteMcpTokenRequest';
import { McpTokenCreatedResponse } from '../models/McpTokenCreatedResponse';
import { McpTokenResponse } from '../models/McpTokenResponse';

/**
 * no description
 */
export class McpApiRequestFactory extends BaseAPIRequestFactory {

    /**
     * Create an MCP bearer token (`maskura_mcp_...`). The plaintext token is returned once and only its hash is stored.
     * @param createMcpTokenRequest 
     */
    public async createMcpToken(createMcpTokenRequest: CreateMcpTokenRequest, _options?: Configuration): Promise<RequestContext> {
        let _config = _options || this.configuration;

        // verify required parameter 'createMcpTokenRequest' is not null or undefined
        if (createMcpTokenRequest === null || createMcpTokenRequest === undefined) {
            throw new RequiredError("McpApi", "createMcpToken", "createMcpTokenRequest");
        }


        // Path Params
        const localVarPath = '/dashboard/api/mcp-tokens';

        // Make Request Context
        const requestContext = _config.baseServer.makeRequestContext(localVarPath, HttpMethod.POST);
        requestContext.setHeaderParam("Accept", "application/json, */*;q=0.8")


        // Body Params
        const contentType = ObjectSerializer.getPreferredMediaType([
            "application/json"
        ]);
        requestContext.setHeaderParam("Content-Type", contentType);
        const serializedBody = ObjectSerializer.stringify(
            ObjectSerializer.serialize(createMcpTokenRequest, "CreateMcpTokenRequest", ""),
            contentType
        );
        requestContext.setBody(serializedBody);

        
        const defaultAuth: SecurityAuthentication | undefined = _config?.authMethods?.default
        if (defaultAuth?.applySecurityAuthentication) {
            await defaultAuth?.applySecurityAuthentication(requestContext);
        }

        return requestContext;
    }

    /**
     * Revoke an MCP bearer token.
     * @param deleteMcpTokenRequest 
     */
    public async deleteMcpToken(deleteMcpTokenRequest: DeleteMcpTokenRequest, _options?: Configuration): Promise<RequestContext> {
        let _config = _options || this.configuration;

        // verify required parameter 'deleteMcpTokenRequest' is not null or undefined
        if (deleteMcpTokenRequest === null || deleteMcpTokenRequest === undefined) {
            throw new RequiredError("McpApi", "deleteMcpToken", "deleteMcpTokenRequest");
        }


        // Path Params
        const localVarPath = '/dashboard/api/mcp-tokens';

        // Make Request Context
        const requestContext = _config.baseServer.makeRequestContext(localVarPath, HttpMethod.DELETE);
        requestContext.setHeaderParam("Accept", "application/json, */*;q=0.8")


        // Body Params
        const contentType = ObjectSerializer.getPreferredMediaType([
            "application/json"
        ]);
        requestContext.setHeaderParam("Content-Type", contentType);
        const serializedBody = ObjectSerializer.stringify(
            ObjectSerializer.serialize(deleteMcpTokenRequest, "DeleteMcpTokenRequest", ""),
            contentType
        );
        requestContext.setBody(serializedBody);

        
        const defaultAuth: SecurityAuthentication | undefined = _config?.authMethods?.default
        if (defaultAuth?.applySecurityAuthentication) {
            await defaultAuth?.applySecurityAuthentication(requestContext);
        }

        return requestContext;
    }

    /**
     * List MCP bearer tokens for the authenticated user (hashes only).
     */
    public async getMcpTokens(_options?: Configuration): Promise<RequestContext> {
        let _config = _options || this.configuration;

        // Path Params
        const localVarPath = '/dashboard/api/mcp-tokens';

        // Make Request Context
        const requestContext = _config.baseServer.makeRequestContext(localVarPath, HttpMethod.GET);
        requestContext.setHeaderParam("Accept", "application/json, */*;q=0.8")


        
        const defaultAuth: SecurityAuthentication | undefined = _config?.authMethods?.default
        if (defaultAuth?.applySecurityAuthentication) {
            await defaultAuth?.applySecurityAuthentication(requestContext);
        }

        return requestContext;
    }

}

export class McpApiResponseProcessor {

    /**
     * Unwraps the actual response sent by the server from the response context and deserializes the response content
     * to the expected objects
     *
     * @params response Response returned by the server for a request to createMcpToken
     * @throws ApiException if the response code was not in [200, 299]
     */
     public async createMcpTokenWithHttpInfo(response: ResponseContext): Promise<HttpInfo<McpTokenCreatedResponse >> {
        const contentType = ObjectSerializer.normalizeMediaType(response.headers["content-type"]);
        if (isCodeInRange("200", response.httpStatusCode)) {
            const body: McpTokenCreatedResponse = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "McpTokenCreatedResponse", ""
            ) as McpTokenCreatedResponse;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        // Work around for missing responses in specification, e.g. for petstore.yaml
        if (response.httpStatusCode >= 200 && response.httpStatusCode <= 299) {
            const body: McpTokenCreatedResponse = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "McpTokenCreatedResponse", ""
            ) as McpTokenCreatedResponse;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        throw new ApiException<string | Blob | undefined>(response.httpStatusCode, "Unknown API Status Code!", await response.getBodyAsAny(), response.headers);
    }

    /**
     * Unwraps the actual response sent by the server from the response context and deserializes the response content
     * to the expected objects
     *
     * @params response Response returned by the server for a request to deleteMcpToken
     * @throws ApiException if the response code was not in [200, 299]
     */
     public async deleteMcpTokenWithHttpInfo(response: ResponseContext): Promise<HttpInfo<void >> {
        const contentType = ObjectSerializer.normalizeMediaType(response.headers["content-type"]);
        if (isCodeInRange("204", response.httpStatusCode)) {
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, undefined);
        }
        if (isCodeInRange("404", response.httpStatusCode)) {
            throw new ApiException<undefined>(response.httpStatusCode, "Token not found", undefined, response.headers);
        }

        // Work around for missing responses in specification, e.g. for petstore.yaml
        if (response.httpStatusCode >= 200 && response.httpStatusCode <= 299) {
            const body: void = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "void", ""
            ) as void;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        throw new ApiException<string | Blob | undefined>(response.httpStatusCode, "Unknown API Status Code!", await response.getBodyAsAny(), response.headers);
    }

    /**
     * Unwraps the actual response sent by the server from the response context and deserializes the response content
     * to the expected objects
     *
     * @params response Response returned by the server for a request to getMcpTokens
     * @throws ApiException if the response code was not in [200, 299]
     */
     public async getMcpTokensWithHttpInfo(response: ResponseContext): Promise<HttpInfo<Array<McpTokenResponse> >> {
        const contentType = ObjectSerializer.normalizeMediaType(response.headers["content-type"]);
        if (isCodeInRange("200", response.httpStatusCode)) {
            const body: Array<McpTokenResponse> = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "Array<McpTokenResponse>", ""
            ) as Array<McpTokenResponse>;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        // Work around for missing responses in specification, e.g. for petstore.yaml
        if (response.httpStatusCode >= 200 && response.httpStatusCode <= 299) {
            const body: Array<McpTokenResponse> = ObjectSerializer.deserialize(
                ObjectSerializer.parse(await response.body.text(), contentType),
                "Array<McpTokenResponse>", ""
            ) as Array<McpTokenResponse>;
            return new HttpInfo(response.httpStatusCode, response.headers, response.body, body);
        }

        throw new ApiException<string | Blob | undefined>(response.httpStatusCode, "Unknown API Status Code!", await response.getBodyAsAny(), response.headers);
    }

}
