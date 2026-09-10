import { ResponseContext, RequestContext, HttpFile, HttpInfo } from '../http/http';
import { Configuration, PromiseConfigurationOptions, wrapOptions } from '../configuration'
import { PromiseMiddleware, Middleware, PromiseMiddlewareWrapper } from '../middleware';

import { ApiKeyResponse } from '../models/ApiKeyResponse';
import { BackendConfigRequest } from '../models/BackendConfigRequest';
import { BackendConfigResponse } from '../models/BackendConfigResponse';
import { BackendType } from '../models/BackendType';
import { CreateKeyRequest } from '../models/CreateKeyRequest';
import { CreateMcpTokenRequest } from '../models/CreateMcpTokenRequest';
import { DeleteKeyRequest } from '../models/DeleteKeyRequest';
import { DeleteMcpTokenRequest } from '../models/DeleteMcpTokenRequest';
import { ListKeyResponse } from '../models/ListKeyResponse';
import { McpTokenCreatedResponse } from '../models/McpTokenCreatedResponse';
import { McpTokenResponse } from '../models/McpTokenResponse';
import { ObjectResponse } from '../models/ObjectResponse';
import { ObservableBackendApi } from './ObservableAPI';

import { BackendApiRequestFactory, BackendApiResponseProcessor} from "../apis/BackendApi";
export class PromiseBackendApi {
    private api: ObservableBackendApi

    public constructor(
        configuration: Configuration,
        requestFactory?: BackendApiRequestFactory,
        responseProcessor?: BackendApiResponseProcessor
    ) {
        this.api = new ObservableBackendApi(configuration, requestFactory, responseProcessor);
    }

    /**
     */
    public getBackendWithHttpInfo(_options?: PromiseConfigurationOptions): Promise<HttpInfo<BackendConfigResponse>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.getBackendWithHttpInfo(observableOptions);
        return result.toPromise();
    }

    /**
     */
    public getBackend(_options?: PromiseConfigurationOptions): Promise<BackendConfigResponse> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.getBackend(observableOptions);
        return result.toPromise();
    }

    /**
     * @param backendConfigRequest
     */
    public putBackendWithHttpInfo(backendConfigRequest: BackendConfigRequest, _options?: PromiseConfigurationOptions): Promise<HttpInfo<BackendConfigResponse>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.putBackendWithHttpInfo(backendConfigRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * @param backendConfigRequest
     */
    public putBackend(backendConfigRequest: BackendConfigRequest, _options?: PromiseConfigurationOptions): Promise<BackendConfigResponse> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.putBackend(backendConfigRequest, observableOptions);
        return result.toPromise();
    }


}



import { ObservableKeysApi } from './ObservableAPI';

import { KeysApiRequestFactory, KeysApiResponseProcessor} from "../apis/KeysApi";
export class PromiseKeysApi {
    private api: ObservableKeysApi

    public constructor(
        configuration: Configuration,
        requestFactory?: KeysApiRequestFactory,
        responseProcessor?: KeysApiResponseProcessor
    ) {
        this.api = new ObservableKeysApi(configuration, requestFactory, responseProcessor);
    }

    /**
     * Create a new API key
     * @param createKeyRequest
     */
    public createKeyWithHttpInfo(createKeyRequest: CreateKeyRequest, _options?: PromiseConfigurationOptions): Promise<HttpInfo<ApiKeyResponse>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.createKeyWithHttpInfo(createKeyRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * Create a new API key
     * @param createKeyRequest
     */
    public createKey(createKeyRequest: CreateKeyRequest, _options?: PromiseConfigurationOptions): Promise<ApiKeyResponse> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.createKey(createKeyRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * Revoke an API key
     * @param deleteKeyRequest
     */
    public deleteKeyWithHttpInfo(deleteKeyRequest: DeleteKeyRequest, _options?: PromiseConfigurationOptions): Promise<HttpInfo<void>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.deleteKeyWithHttpInfo(deleteKeyRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * Revoke an API key
     * @param deleteKeyRequest
     */
    public deleteKey(deleteKeyRequest: DeleteKeyRequest, _options?: PromiseConfigurationOptions): Promise<void> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.deleteKey(deleteKeyRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * List API keys for the authenticated user
     */
    public getKeysWithHttpInfo(_options?: PromiseConfigurationOptions): Promise<HttpInfo<Array<ListKeyResponse>>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.getKeysWithHttpInfo(observableOptions);
        return result.toPromise();
    }

    /**
     * List API keys for the authenticated user
     */
    public getKeys(_options?: PromiseConfigurationOptions): Promise<Array<ListKeyResponse>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.getKeys(observableOptions);
        return result.toPromise();
    }


}



import { ObservableMcpApi } from './ObservableAPI';

import { McpApiRequestFactory, McpApiResponseProcessor} from "../apis/McpApi";
export class PromiseMcpApi {
    private api: ObservableMcpApi

    public constructor(
        configuration: Configuration,
        requestFactory?: McpApiRequestFactory,
        responseProcessor?: McpApiResponseProcessor
    ) {
        this.api = new ObservableMcpApi(configuration, requestFactory, responseProcessor);
    }

    /**
     * Create an MCP bearer token (`maskura_mcp_...`). The plaintext token is returned once and only its hash is stored.
     * @param createMcpTokenRequest
     */
    public createMcpTokenWithHttpInfo(createMcpTokenRequest: CreateMcpTokenRequest, _options?: PromiseConfigurationOptions): Promise<HttpInfo<McpTokenCreatedResponse>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.createMcpTokenWithHttpInfo(createMcpTokenRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * Create an MCP bearer token (`maskura_mcp_...`). The plaintext token is returned once and only its hash is stored.
     * @param createMcpTokenRequest
     */
    public createMcpToken(createMcpTokenRequest: CreateMcpTokenRequest, _options?: PromiseConfigurationOptions): Promise<McpTokenCreatedResponse> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.createMcpToken(createMcpTokenRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * Revoke an MCP bearer token.
     * @param deleteMcpTokenRequest
     */
    public deleteMcpTokenWithHttpInfo(deleteMcpTokenRequest: DeleteMcpTokenRequest, _options?: PromiseConfigurationOptions): Promise<HttpInfo<void>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.deleteMcpTokenWithHttpInfo(deleteMcpTokenRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * Revoke an MCP bearer token.
     * @param deleteMcpTokenRequest
     */
    public deleteMcpToken(deleteMcpTokenRequest: DeleteMcpTokenRequest, _options?: PromiseConfigurationOptions): Promise<void> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.deleteMcpToken(deleteMcpTokenRequest, observableOptions);
        return result.toPromise();
    }

    /**
     * List MCP bearer tokens for the authenticated user (hashes only).
     */
    public getMcpTokensWithHttpInfo(_options?: PromiseConfigurationOptions): Promise<HttpInfo<Array<McpTokenResponse>>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.getMcpTokensWithHttpInfo(observableOptions);
        return result.toPromise();
    }

    /**
     * List MCP bearer tokens for the authenticated user (hashes only).
     */
    public getMcpTokens(_options?: PromiseConfigurationOptions): Promise<Array<McpTokenResponse>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.getMcpTokens(observableOptions);
        return result.toPromise();
    }


}



import { ObservableObjectsApi } from './ObservableAPI';

import { ObjectsApiRequestFactory, ObjectsApiResponseProcessor} from "../apis/ObjectsApi";
export class PromiseObjectsApi {
    private api: ObservableObjectsApi

    public constructor(
        configuration: Configuration,
        requestFactory?: ObjectsApiRequestFactory,
        responseProcessor?: ObjectsApiResponseProcessor
    ) {
        this.api = new ObservableObjectsApi(configuration, requestFactory, responseProcessor);
    }

    /**
     * List all objects in the store
     */
    public listObjectsWithHttpInfo(_options?: PromiseConfigurationOptions): Promise<HttpInfo<Array<ObjectResponse>>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.listObjectsWithHttpInfo(observableOptions);
        return result.toPromise();
    }

    /**
     * List all objects in the store
     */
    public listObjects(_options?: PromiseConfigurationOptions): Promise<Array<ObjectResponse>> {
        const observableOptions = wrapOptions(_options);
        const result = this.api.listObjects(observableOptions);
        return result.toPromise();
    }


}



