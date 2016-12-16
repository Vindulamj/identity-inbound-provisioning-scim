package org.wso2.carbon.identity.scim.common.utils;

import java.util.Map;

/**
 * this class is the blue print of authentication schemas used in ServiceProvidesConfig.
 */
public class AuthenticationSchema {

    private String name;
    private String description;
    private String specUri;
    private String documentationUri;
    private String type;
    private String primary;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getSpecUri() {
        return specUri;
    }

    public void setSpecUri(String specUri) {
        this.specUri = specUri;
    }

    public String getDocumentationUri() {
        return documentationUri;
    }

    public void setDocumentationUri(String documentationUri) {
        this.documentationUri = documentationUri;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getPrimary() {
        return primary;
    }

    public void setPrimary(String primary) {
        this.primary = primary;
    }

    public void setProperties(Map<String, String> properties) {
        for (String property : properties.keySet()) {
            if (property.equals("name")) {
                setName(properties.get(property));
            } else if (property.equals("description")) {
                setDescription(properties.get(property));
            } else if (property.equals("specUri")) {
                setSpecUri(properties.get(property));
            } else if (property.equals("documentationUri")) {
                setDocumentationUri(properties.get(property));
            } else if (property.equals("type")) {
                setType(properties.get(property));
            } else if (property.equals("primary")) {
                setPrimary(properties.get(property));
            }
        }
    }
}


