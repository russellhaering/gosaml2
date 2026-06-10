// Copyright 2025 Russell Haering et al.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"fmt"
	"strconv"
	"time"

	xmltree "github.com/russellhaering/gosaml2/v2/internal/xmltree"
)

const (
	metadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"
	dsigNamespace     = "http://www.w3.org/2000/09/xmldsig#"
)

// parseBool matches encoding/xml's bool parsing (strconv.ParseBool); an
// empty or unparseable value yields false, as encoding/xml leaves the
// zero value.
func parseBool(s string) bool {
	if s == "" {
		return false
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		return false
	}
	return b
}

// EntityDescriptorFromElement extracts an EntityDescriptor from an
// md:EntityDescriptor element.
func EntityDescriptorFromElement(el *xmltree.Element) (*EntityDescriptor, error) {
	if el == nil || el.Tag != "EntityDescriptor" {
		tag := "<nil>"
		if el != nil {
			tag = el.Tag
		}
		return nil, fmt.Errorf("saml: expected element EntityDescriptor, got %s", tag)
	}

	ed := &EntityDescriptor{
		XMLName:  xmlName(metadataNamespace, "EntityDescriptor"),
		EntityID: el.SelectAttrValue("entityID", ""),
	}
	if v := el.SelectAttrValue("validUntil", ""); v != "" {
		// encoding/xml accepts RFC3339; mirror it (zero value on parse error).
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			ed.ValidUntil = ts
		}
	}
	if sp := el.SelectLastElement("SPSSODescriptor"); sp != nil {
		ed.SPSSODescriptor = spSSODescriptorFromElement(sp)
	}
	if idp := el.SelectLastElement("IDPSSODescriptor"); idp != nil {
		ed.IDPSSODescriptor = idpSSODescriptorFromElement(idp)
	}
	if ext := el.SelectLastElement("Extensions"); ext != nil {
		ed.Extensions = extensionsFromElement(ext)
	}
	return ed, nil
}

func spSSODescriptorFromElement(el *xmltree.Element) *SPSSODescriptor {
	d := &SPSSODescriptor{
		XMLName:                    xmlName(metadataNamespace, "SPSSODescriptor"),
		AuthnRequestsSigned:        parseBool(el.SelectAttrValue("AuthnRequestsSigned", "")),
		WantAssertionsSigned:       parseBool(el.SelectAttrValue("WantAssertionsSigned", "")),
		ProtocolSupportEnumeration: el.SelectAttrValue("protocolSupportEnumeration", ""),
	}
	for _, child := range el.ChildElements() {
		switch child.Tag {
		case "KeyDescriptor":
			d.KeyDescriptors = append(d.KeyDescriptors, keyDescriptorFromElement(child))
		case "SingleLogoutService":
			d.SingleLogoutServices = append(d.SingleLogoutServices, endpointFromElement(child))
		case "NameIDFormat":
			d.NameIDFormats = append(d.NameIDFormats, child.Text())
		case "AssertionConsumerService":
			d.AssertionConsumerServices = append(d.AssertionConsumerServices, indexedEndpointFromElement(child))
		case "Extensions":
			d.Extensions = extensionsFromElement(child)
		}
	}
	return d
}

func idpSSODescriptorFromElement(el *xmltree.Element) *IDPSSODescriptor {
	d := &IDPSSODescriptor{
		XMLName:                    xmlName(metadataNamespace, "IDPSSODescriptor"),
		ProtocolSupportEnumeration: el.SelectAttrValue("protocolSupportEnumeration", ""),
		WantAuthnRequestsSigned:    parseBool(el.SelectAttrValue("WantAuthnRequestsSigned", "")),
	}
	for _, child := range el.ChildElements() {
		switch child.Tag {
		case "KeyDescriptor":
			d.KeyDescriptors = append(d.KeyDescriptors, keyDescriptorFromElement(child))
		case "NameIDFormat":
			d.NameIDFormats = append(d.NameIDFormats, NameIDFormat{
				XMLName: xmlName(metadataNamespace, "NameIDFormat"),
				Value:   child.Text(),
			})
		case "SingleSignOnService":
			d.SingleSignOnServices = append(d.SingleSignOnServices, SingleSignOnService{
				XMLName:  xmlName(metadataNamespace, "SingleSignOnService"),
				Binding:  child.SelectAttrValue("Binding", ""),
				Location: child.SelectAttrValue("Location", ""),
			})
		case "SingleLogoutService":
			d.SingleLogoutServices = append(d.SingleLogoutServices, SingleLogoutService{
				XMLName:  xmlName(metadataNamespace, "SingleLogoutService"),
				Binding:  child.SelectAttrValue("Binding", ""),
				Location: child.SelectAttrValue("Location", ""),
			})
		case "Attribute":
			d.Attributes = append(d.Attributes, metadataAttributeFromElement(child))
		case "Extensions":
			d.Extensions = extensionsFromElement(child)
		}
	}
	return d
}

func keyDescriptorFromElement(el *xmltree.Element) KeyDescriptor {
	kd := KeyDescriptor{
		XMLName: xmlName(metadataNamespace, "KeyDescriptor"),
		Use:     el.SelectAttrValue("use", ""),
	}
	if keyInfo := el.SelectLastElement("KeyInfo"); keyInfo != nil {
		kd.KeyInfo.XMLName = xmlName(dsigNamespace, "KeyInfo")
		if x509Data := keyInfo.SelectLastElement("X509Data"); x509Data != nil {
			kd.KeyInfo.X509Data.XMLName = xmlName(dsigNamespace, "X509Data")
			for _, cert := range x509Data.SelectElements("X509Certificate") {
				kd.KeyInfo.X509Data.X509Certificates = append(kd.KeyInfo.X509Data.X509Certificates,
					X509Certificate{
						XMLName: xmlName(dsigNamespace, "X509Certificate"),
						Data:    cert.Text(),
					})
			}
		}
	}
	for _, em := range el.SelectElements("EncryptionMethod") {
		kd.EncryptionMethods = append(kd.EncryptionMethods, *encryptionMethodFromElement(em))
	}
	return kd
}

func endpointFromElement(el *xmltree.Element) Endpoint {
	return Endpoint{
		Binding:          el.SelectAttrValue("Binding", ""),
		Location:         el.SelectAttrValue("Location", ""),
		ResponseLocation: el.SelectAttrValue("ResponseLocation", ""),
	}
}

func indexedEndpointFromElement(el *xmltree.Element) IndexedEndpoint {
	ie := IndexedEndpoint{
		Binding:  el.SelectAttrValue("Binding", ""),
		Location: el.SelectAttrValue("Location", ""),
	}
	if idx := el.SelectAttrValue("index", ""); idx != "" {
		ie.Index, _ = strconv.Atoi(idx)
	}
	return ie
}

func metadataAttributeFromElement(el *xmltree.Element) Attribute {
	attr := Attribute{
		XMLName:      xmlName(AssertionNamespace, "Attribute"),
		FriendlyName: el.SelectAttrValue("FriendlyName", ""),
		Name:         el.SelectAttrValue("Name", ""),
		NameFormat:   el.SelectAttrValue("NameFormat", ""),
	}
	for _, val := range el.SelectElements("AttributeValue") {
		attr.Values = append(attr.Values, AttributeValue{
			XMLName: xmlName(AssertionNamespace, "AttributeValue"),
			Type:    val.SelectAttrValue("xsi:type", ""),
			Value:   val.Text(),
		})
	}
	return attr
}

func extensionsFromElement(el *xmltree.Element) *Extensions {
	ext := &Extensions{}
	if dm := el.SelectLastElement("DigestMethod"); dm != nil {
		ext.DigestMethod = &DigestMethod{Algorithm: dm.SelectAttrValue("Algorithm", "")}
	}
	if sm := el.SelectLastElement("SigningMethod"); sm != nil {
		ext.SigningMethod = &SigningMethod{
			Algorithm:  sm.SelectAttrValue("Algorithm", ""),
			MinKeySize: sm.SelectAttrValue("MinKeySize", ""),
			MaxKeySize: sm.SelectAttrValue("MaxKeySize", ""),
		}
	}
	return ext
}
