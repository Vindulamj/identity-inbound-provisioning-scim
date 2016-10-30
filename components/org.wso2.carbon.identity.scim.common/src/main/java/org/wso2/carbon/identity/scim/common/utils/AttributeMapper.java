/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.scim.common.utils;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.charon.core.v2.attributes.Attribute;
import org.wso2.charon.core.v2.attributes.ComplexAttribute;
import org.wso2.charon.core.v2.attributes.DefaultAttributeFactory;
import org.wso2.charon.core.v2.attributes.MultiValuedAttribute;
import org.wso2.charon.core.v2.attributes.SimpleAttribute;
import org.wso2.charon.core.v2.exceptions.BadRequestException;
import org.wso2.charon.core.v2.exceptions.CharonException;
import org.wso2.charon.core.v2.exceptions.NotFoundException;
import org.wso2.charon.core.v2.objects.AbstractSCIMObject;
import org.wso2.charon.core.v2.objects.Group;
import org.wso2.charon.core.v2.objects.SCIMObject;
import org.wso2.charon.core.v2.objects.User;
import org.wso2.charon.core.v2.schema.*;
import org.wso2.charon.core.v2.utils.AttributeUtil;
import sun.java2d.pipe.SpanShapeRenderer;


import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * This class is responsible for converting SCIM attributes in a SCIM object to
 * carbon claims and vice versa
 */
public class AttributeMapper {

    private static Log log = LogFactory.getLog(AttributeMapper.class);
    private static final boolean debug = log.isDebugEnabled();


    /**
     * Return claims as a map of <ClaimUri (which is mapped to SCIM attribute uri),ClaimValue>
     * TODO : This method should be broken into smaller methods for code reuse
     * TODO : This method SHOULD be recoded. MUST implement loops
     *
     * @param scimObject
     * @return
     */
    public static Map<String, String> getClaimsMap(AbstractSCIMObject scimObject) throws CharonException {
        Map<String, String> claimsMap = new HashMap<>();
        Map<String, Attribute> attributeList = scimObject.getAttributeList();
        for (Map.Entry<String, Attribute> attributeEntry : attributeList.entrySet()) {
            Attribute attribute = attributeEntry.getValue();
            // if the attribute is password, skip it
            if (SCIMConstants.UserSchemaConstants.PASSWORD.equals(attribute.getName())) {
                continue;
            }
            if (attribute instanceof SimpleAttribute) {
                String attributeURI = attribute.getURI();
                if (((SimpleAttribute) attribute).getValue() != null) {
                    String attributeValue = String.valueOf(((SimpleAttribute) attribute).getValue());
                    // set attribute URI as the claim URI
                    claimsMap.put(attributeURI, attributeValue);
                }
            } else if (attribute instanceof MultiValuedAttribute) {
                MultiValuedAttribute multiValAttribute = (MultiValuedAttribute) attribute;
                // get the URI of root attribute
                String attributeURI = multiValAttribute.getURI();
                // check if values are set as simple attributes
                List<Object> attributeValues = multiValAttribute.getAttributePrimitiveValues();
                if (CollectionUtils.isNotEmpty(attributeValues)) {
                    String values = null;
                    for (Object attributeValue : attributeValues) {
                        if (values != null) {
                            values += attributeValue + ",";
                        } else {
                            values = attributeValue + ",";
                        }
                    }
                    claimsMap.put(attributeURI, values);
                }
                // check if values are set as complex values
                // NOTE: in carbon, we only support storing of type and value of
                // a multi-valued attribute
                List<Attribute> complexAttributeList = multiValAttribute.getAttributeValues();
                for (Attribute complexAttribute : complexAttributeList) {
                    Map<String, Attribute> subAttributes =
                            ((ComplexAttribute) complexAttribute).getSubAttributesList();
                    SimpleAttribute typeAttribute =
                            (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.TYPE);
                    String valueAttriubuteURI;
                    // construct attribute URI
                    if (typeAttribute != null) {
                        String typeValue = (String) typeAttribute.getValue();
                        valueAttriubuteURI = attributeURI + "." + typeValue;
                    } else {
                        valueAttriubuteURI = attributeURI;
                    }
                    SimpleAttribute valueAttribute =
                            (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.VALUE);
                    if (valueAttribute != null && valueAttribute.getValue() != null) {
                        // put it in claims
                        claimsMap.put(valueAttriubuteURI,String.valueOf(valueAttribute.getStringValue()));

                    }
                }
            } else if (attribute instanceof ComplexAttribute) {
                // reading attributes list of the complex attribute
                ComplexAttribute complexAttribute = (ComplexAttribute) attribute;
                Map<String, Attribute> attributes = null;
                if (complexAttribute.getSubAttributesList() != null &&
                        MapUtils.isNotEmpty(complexAttribute.getSubAttributesList())) {
                    attributes = complexAttribute.getSubAttributesList();
                }
                if (attributes != null) {
                    for (Attribute entry : attributes.values()) {
                        // if the attribute a simple attribute
                        if (entry instanceof SimpleAttribute) {
                            SimpleAttribute simpleAttribute = (SimpleAttribute) entry;
                            if (simpleAttribute != null && simpleAttribute.getValue() != null) {
                                claimsMap.put(entry.getURI(), String.valueOf(simpleAttribute.getValue()));
                            }
                        } else if (entry instanceof MultiValuedAttribute) {
                            MultiValuedAttribute multiValAttribute = (MultiValuedAttribute) entry;
                            // get the URI of root attribute
                            String attributeURI = multiValAttribute.getURI();
                            // check if values are set as simple attributes
                            List<Object> attributeValues = multiValAttribute.getAttributePrimitiveValues();
                            if (CollectionUtils.isNotEmpty(attributeValues)) {
                                String values = null;
                                for (Object attributeValue : attributeValues) {
                                    if (values != null) {
                                        values += attributeValue + ",";
                                    } else {
                                        values = attributeValue + ",";
                                    }
                                }
                                claimsMap.put(attributeURI, values);
                            }
                            // check if values are set as complex values
                            // NOTE: in carbon, we only support storing of type and
                            // value of a multi-valued attribute
                            List<Attribute> complexAttributeList = multiValAttribute.getAttributeValues();
                            for (Attribute complexAttrib : complexAttributeList) {
                                Map<String, Attribute> subAttributes =
                                        ((ComplexAttribute) complexAttrib).getSubAttributesList();
                                SimpleAttribute typeAttribute =
                                        (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.TYPE);
                                String valueAttriubuteURI;
                                // construct attribute URI
                                if (typeAttribute != null) {
                                    String typeValue = (String) typeAttribute.getValue();
                                    valueAttriubuteURI = attributeURI + "." + typeValue;
                                } else {
                                    valueAttriubuteURI = attributeURI;
                                }
                                SimpleAttribute valueAttribute =
                                        (SimpleAttribute) subAttributes.get(SCIMConstants.CommonSchemaConstants.VALUE);
                                if (valueAttribute != null && valueAttribute.getValue() != null) {
                                    // put it in claims
                                    claimsMap.put(valueAttriubuteURI,String.valueOf(valueAttribute.getValue()));

                                }
                            }

                        } else if (entry instanceof ComplexAttribute) {
                            // reading attributes list of the complex attribute
                            ComplexAttribute entryOfComplexAttribute = (ComplexAttribute) entry;
                            Map<String, Attribute> entryAttributes = null;
                            if (entryOfComplexAttribute.getSubAttributesList() != null &&
                                    MapUtils.isNotEmpty(entryOfComplexAttribute.getSubAttributesList())) {
                                entryAttributes = entryOfComplexAttribute.getSubAttributesList();
                            } else if (entryOfComplexAttribute.getSubAttributesList() != null &&
                                    MapUtils.isNotEmpty(entryOfComplexAttribute.getSubAttributesList())) {
                                entryAttributes = entryOfComplexAttribute.getSubAttributesList();
                            }
                            for (Attribute subEntry : entryAttributes.values()) {
                                // if the attribute a simple attribute
                                if (subEntry instanceof SimpleAttribute) {
                                    SimpleAttribute simpleAttribute = (SimpleAttribute) subEntry;
                                    if (simpleAttribute != null && simpleAttribute.getValue() != null) {
                                        claimsMap.put(subEntry.getURI(), String.valueOf(simpleAttribute.getValue()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return claimsMap;
    }


    /**
     * Construct the SCIM Object given the attribute URIs and attribute values of the object.
     *
     * @param attributes
     * @param scimObjectType
     * @return
     */
    public static SCIMObject constructSCIMObjectFromAttributes(Map<String, String> attributes,
                                                               int scimObjectType)
            throws CharonException, NotFoundException, BadRequestException {
        SCIMObject scimObject = null;
        switch (scimObjectType) {
            case 2:
                scimObject = new Group();
                log.debug("Building Group Object");
                break;
            case 1:
                scimObject = new User();
                log.debug("Building User Object");
                break;
            default:
                break;
        }
        for (Map.Entry<String, String> attributeEntry : attributes.entrySet()) {

            if (debug) {
                log.debug("AttributeKey: " + attributeEntry.getKey() + " AttributeValue:" +
                        attributeEntry.getValue());
            }

            String attributeURI = attributeEntry.getKey();
            String[] attributeURIParts = attributeURI.split(":");
            String attributeNameString = attributeURIParts[attributeURIParts.length - 1];
            String[] attributeNames = attributeNameString.split("\\.");

            if (attributeNames.length == 1) {
                //get attribute schema
                AttributeSchema attributeSchema = getAttributeSchema(attributeNames[0], scimObjectType);

                if (attributeSchema != null) {
                    //either simple valued or multi-valued with simple attributes
                    if (isMultivalued(attributeNames[0], scimObjectType)) {
                        //see whether multiple values are there
                        String value = attributeEntry.getValue();
                        Object[] values = value.split(",");
                        //create attribute
                        MultiValuedAttribute multiValuedAttribute = new MultiValuedAttribute(
                                attributeSchema.getName());
                        //set values
                        multiValuedAttribute.setAttributePrimitiveValues(Arrays.asList(values));
                        //set attribute in scim object
                        DefaultAttributeFactory.createAttribute(attributeSchema, multiValuedAttribute);
                        ((AbstractSCIMObject) scimObject).setAttribute(multiValuedAttribute);

                    } else {
                        //convert attribute to relevant type
                        Object attributeValueObject = AttributeUtil.getAttributeValueFromString(
                                attributeEntry.getValue(), attributeSchema.getType());

                        //create attribute
                        SimpleAttribute simpleAttribute = new SimpleAttribute(attributeNames[0],
                                attributeValueObject);
                        DefaultAttributeFactory.createAttribute(attributeSchema, simpleAttribute);
                        //set attribute in the SCIM object
                        ((AbstractSCIMObject) scimObject).setAttribute(simpleAttribute);
                    }
                }
            } else if (attributeNames.length == 2) {
                //get parent attribute name
                String parentAttributeName = attributeNames[0];
                //get parent attribute schema
                AttributeSchema parentAttributeSchema = getAttributeSchema(parentAttributeName,
                        scimObjectType);
                /*differenciate between sub attribute of Complex attribute and a Multivalued attribute
                with complex value*/
                if (isMultivalued(parentAttributeName, scimObjectType)) {
                    //create map with complex value
                    SimpleAttribute typeSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE,attributeNames[1]);
                    SimpleAttribute valueSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.VALUE,
                            AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                    parentAttributeSchema.getType()));

                    Object type = "default";
                    Object value = "default";
                    if(typeSimpleAttribute.getValue() !=null){
                        type = typeSimpleAttribute.getValue();
                    }
                    if(valueSimpleAttribute.getValue() != null){
                        value = valueSimpleAttribute.getValue();
                    }
                    String complexName = parentAttributeName+"_"+value+"_"+type;
                    ComplexAttribute complexAttribute = new ComplexAttribute(complexName);
                    complexAttribute.setSubAttribute(typeSimpleAttribute);
                    complexAttribute.setSubAttribute(valueSimpleAttribute);

                    //check whether parent multivalued attribute already exists
                    if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeName)) {
                        //create attribute value as complex value
                        MultiValuedAttribute multiValuedAttribute =
                                (MultiValuedAttribute) scimObject.getAttribute(parentAttributeName);
                        multiValuedAttribute.setAttributeValue(complexAttribute);
                    } else {
                        //create the attribute and set it in the scim object
                        MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(
                                parentAttributeName);
                        multivaluedAttribute.setAttributeValue(complexAttribute);
                        DefaultAttributeFactory.createAttribute(parentAttributeSchema, multivaluedAttribute);
                        ((AbstractSCIMObject) scimObject).setAttribute(multivaluedAttribute);
                    }
                } else {
                    //sub attribute of a complex attribute
                    AttributeSchema subAttributeSchema = getAttributeSchema(attributeNames[1], scimObjectType);
                    //we assume sub attribute is simple attribute
                    SimpleAttribute simpleAttribute =
                            new SimpleAttribute(attributeNames[1],
                                    AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                            subAttributeSchema.getType()));
                    DefaultAttributeFactory.createAttribute(subAttributeSchema, simpleAttribute);
                    //check whether parent attribute exists.
                    if (((AbstractSCIMObject) scimObject).isAttributeExist(parentAttributeName)) {
                        ComplexAttribute complexAttribute =
                                (ComplexAttribute) scimObject.getAttribute(parentAttributeName);
                        complexAttribute.setSubAttribute(simpleAttribute);
                    } else {
                        //create parent attribute and set sub attribute
                        ComplexAttribute complexAttribute = new ComplexAttribute(parentAttributeName);
                        complexAttribute.setSubAttribute(simpleAttribute);
                        DefaultAttributeFactory.createAttribute(parentAttributeSchema, complexAttribute);
                        ((AbstractSCIMObject) scimObject).setAttribute(complexAttribute);
                    }

                }
            } else if (attributeNames.length == 3) {
                //get immediate parent attribute name
                String immediateParentAttributeName = attributeNames[1];
                AttributeSchema immediateParentAttributeSchema = getAttributeSchema(immediateParentAttributeName,
                        scimObjectType);
                /*differenciate between sub attribute of Complex attribute and a Multivalued attribute
                with complex value*/
                if (isMultivalued(immediateParentAttributeName, scimObjectType)) {
                    //create map with complex value
                    SimpleAttribute typeSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.TYPE,attributeNames[1]);
                    SimpleAttribute valueSimpleAttribute = new SimpleAttribute(SCIMConstants.CommonSchemaConstants.VALUE,
                            AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                    immediateParentAttributeSchema.getType()));

                    Object type = "default";
                    Object value = "default";
                    if(typeSimpleAttribute.getValue() !=null){
                        type = typeSimpleAttribute.getValue();
                    }
                    if(valueSimpleAttribute.getValue() != null){
                        value = valueSimpleAttribute.getValue();
                    }
                    String complexName = immediateParentAttributeName+"_"+value+"_"+type;
                    ComplexAttribute complexAttribute = new ComplexAttribute(complexName);
                    complexAttribute.setSubAttribute(typeSimpleAttribute);
                    complexAttribute.setSubAttribute(valueSimpleAttribute);

                    //check whether parent multivalued attribute already exists
                    if (((AbstractSCIMObject) scimObject).isAttributeExist(immediateParentAttributeName)) {
                        //create attribute value as complex value
                        MultiValuedAttribute multiValuedAttribute =
                                (MultiValuedAttribute) scimObject.getAttribute(immediateParentAttributeName);
                        multiValuedAttribute.setAttributeValue(complexAttribute);
                    } else {
                        //create the attribute and set it in the scim object
                        MultiValuedAttribute multivaluedAttribute = new MultiValuedAttribute(
                                immediateParentAttributeName);
                        multivaluedAttribute.setAttributeValue(complexAttribute);
                        DefaultAttributeFactory.createAttribute(immediateParentAttributeSchema, multivaluedAttribute);
                        ((AbstractSCIMObject) scimObject).setAttribute(multivaluedAttribute);
                    }
                } else {
                    //sub attribute of a complex attribute
                    AttributeSchema subAttributeSchema = getAttributeSchema(attributeNames[2], attributeNames[1], scimObjectType);
                    //we assume sub attribute is simple attribute
                    SimpleAttribute simpleAttribute = new SimpleAttribute(attributeNames[2],
                            AttributeUtil.getAttributeValueFromString(attributeEntry.getValue(),
                                    subAttributeSchema.getType()));
                    DefaultAttributeFactory.createAttribute(subAttributeSchema, simpleAttribute);

                    // check if the super parent exist
                    boolean superParentExist = ((AbstractSCIMObject) scimObject).isAttributeExist(attributeNames[0]);
                    if (superParentExist) {
                        ComplexAttribute superParentAttribute = (ComplexAttribute) ((AbstractSCIMObject) scimObject).getAttribute(attributeNames[0]);
                        // check if the immediate parent exist
                        boolean immediateParentExist = superParentAttribute.isSubAttributeExist(immediateParentAttributeName);
                        if (immediateParentExist) {
                            // both the parent and super parent exists
                            ComplexAttribute immediateParentAttribute = (ComplexAttribute) superParentAttribute.getSubAttribute(immediateParentAttributeName);
                            immediateParentAttribute.setSubAttribute(simpleAttribute);
                        } else { // immediate parent does not exist
                            ComplexAttribute immediateParentAttribute = new ComplexAttribute(immediateParentAttributeName);
                            immediateParentAttribute.setSubAttribute(simpleAttribute);
                            DefaultAttributeFactory.createAttribute(immediateParentAttributeSchema, immediateParentAttribute);
                            // created the immediate parent and now set to super
                            superParentAttribute.setSubAttribute(immediateParentAttribute);
                        }
                    } else { // now have to create both the super parent and immediate parent
                        // immediate first
                        ComplexAttribute immediateParentAttribute = new ComplexAttribute(immediateParentAttributeName);
                        immediateParentAttribute.setSubAttribute(simpleAttribute);
                        DefaultAttributeFactory.createAttribute(immediateParentAttributeSchema, immediateParentAttribute);
                        // now super parent
                        ComplexAttribute superParentAttribute = new ComplexAttribute(attributeNames[0]);
                        superParentAttribute.setSubAttribute(immediateParentAttribute);
                        AttributeSchema superParentAttributeSchema = getAttributeSchema(attributeNames[0], scimObjectType);
                        DefaultAttributeFactory.createAttribute(superParentAttributeSchema, superParentAttribute);
                        // now add the super to the scim object
                        ((AbstractSCIMObject) scimObject).setAttribute(superParentAttribute);
                    }
                }
            }
        }
        return scimObject;
    }

    private static boolean isMultivalued(String attributeName, int scimObjectType) {
        AttributeSchema attributeSchema = getAttributeSchema(attributeName, scimObjectType);
        if (attributeSchema != null) {
            return attributeSchema.getMultiValued();
        }
        return false;
    }

    private static AttributeSchema getAttributeSchema(String attributeName, int scimObjectType) {
        return getAttributeSchema(attributeName, null, scimObjectType);
    }

    private static AttributeSchema getAttributeSchema(String attributeName, String parentAttributeName, int scimObjectType) {
        ResourceTypeSchema resourceSchema = getResourceSchema(scimObjectType);
        if (resourceSchema != null) {
            List<AttributeSchema> attributeSchemas = resourceSchema.getAttributesList();
            for (AttributeSchema attributeSchema : attributeSchemas) {
                if (attributeName.equals(attributeSchema.getName())) {
                    if (parentAttributeName == null ||
                            attributeSchema.getURI().contains(parentAttributeName)) {
                        return attributeSchema;
                    }
                }
                //check for sub attributes
                List<SCIMAttributeSchema> subAttributeSchemas =
                        ((SCIMAttributeSchema) attributeSchema).getSubAttributeSchemas();
                if (CollectionUtils.isNotEmpty(subAttributeSchemas)) {
                    for (SCIMAttributeSchema subAttributeSchema : subAttributeSchemas) {
                        if (attributeName.equals(subAttributeSchema.getName())) {
                            if (parentAttributeName == null ||
                                    subAttributeSchema.getURI().contains(parentAttributeName)) {
                                return subAttributeSchema;
                            }
                        }
                    }
                }
                // check for attributes of the attribute
                List<SCIMAttributeSchema> attribSchemas = ((SCIMAttributeSchema) attributeSchema).getSubAttributeSchemas();
                if (CollectionUtils.isNotEmpty(attribSchemas)) {
                    for (SCIMAttributeSchema attribSchema : attribSchemas) {
                        // if the attribute a simple attribute
                        if (attributeName.equals(attribSchema.getName())) {
                            return attribSchema;
                        }
                        // if the attribute a complex attribute having sub attributes
                        //check for sub attributes
                        List<SCIMAttributeSchema> subSubAttribSchemas =
                                ((SCIMAttributeSchema) attribSchema).getSubAttributeSchemas();
                        if (CollectionUtils.isNotEmpty(subSubAttribSchemas)) {
                            for (SCIMAttributeSchema subSubAttribSchema : subSubAttribSchemas) {
                                if (attributeName.equals(subSubAttribSchema.getName())) {
                                    if (parentAttributeName == null ||
                                            subSubAttribSchema.getURI().contains(parentAttributeName)) {
                                        return subSubAttribSchema;
                                    }
                                }
                            }
                        }
                        // check for attributes
                        List<SCIMAttributeSchema> attributSchemas = ((SCIMAttributeSchema) attribSchema).getSubAttributeSchemas();
                        if (CollectionUtils.isNotEmpty(attributSchemas)) {
                            for (SCIMAttributeSchema atttribSchema : attributSchemas) {
                                if (attributeName.equals(atttribSchema.getName())) {
                                    if (parentAttributeName == null ||
                                            atttribSchema.getURI().contains(parentAttributeName)) {
                                        return atttribSchema;
                                    }
                                }
                            }
                        }
                    }

                }
            }
        }
        return null;
    }

    private static ResourceTypeSchema getResourceSchema(int scimObjectType) {
        ResourceTypeSchema resourceSchema = null;
        switch (scimObjectType) {
            case 1:
                resourceSchema = SCIMResourceSchemaManager.getInstance().getUserResourceSchema();
                break;
            case 2:
                resourceSchema = SCIMSchemaDefinitions.SCIM_GROUP_SCHEMA;
                break;
            default:
                break;
        }
        return resourceSchema;
    }
}
