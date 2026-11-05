<template>
  <base-form
    :form="form"
    :meta="meta"
    :schema="schema"
    :isLoading="isLoading"
  >
    <form-group-identifier namespace="id"
      :column-label="$i18n.t('PKI Provider Name')"
      :disabled="!isNew && !isClone"
    />

    <form-group-proto namespace="proto"
      :column-label="$i18n.t('Protocol')"
      :text="$i18n.t('Protocol to use to contact the EJBCA REST API.')"
    />

    <form-group-host namespace="host"
      :column-label="$i18n.t('Host')"
      :text="$i18n.t('Host which hosts the EJBCA REST API.')"
    />

    <form-group-port namespace="port"
      :column-label="$i18n.t('Port')"
      :text="$i18n.t('Port on which to contact the EJBCA REST API.')"
    />

    <form-group-client-cert-path namespace="client_cert_path"
      :column-label="$i18n.t('API client certificate file')"
      :title="$i18n.t('Upload client certificate file')"
      :text="$i18n.t('Client certificate used to authenticate against the EJBCA REST API.')"
    />

    <form-group-client-key-path namespace="client_key_path"
      :column-label="$i18n.t('API client key file')"
      :title="$i18n.t('Upload client key file')"
      :text="$i18n.t('Private key of the API client certificate.')"
    />

    <form-group-api-ca-path namespace="api_ca_path"
      :column-label="$i18n.t('API CA certificate file')"
      :title="$i18n.t('Upload CA certificate file')"
      :text="$i18n.t('CA certificate used to validate the EJBCA TLS certificate. The system trust store is used when empty.')"
    />

    <form-group-ca-name namespace="ca_name"
      :column-label="$i18n.t('CA Name')"
      :text="$i18n.t('Name of the EJBCA certificate authority issuing the certificates.')"
    />

    <form-group-certificate-profile namespace="certificate_profile"
      :column-label="$i18n.t('Certificate Profile')"
      :text="$i18n.t('EJBCA certificate profile name.')"
    />

    <form-group-end-entity-profile namespace="end_entity_profile"
      :column-label="$i18n.t('End Entity Profile')"
      :text="$i18n.t('EJBCA end entity profile name.')"
    />

    <form-group-key-algorithm namespace="key_algorithm"
      :column-label="$i18n.t('Key Algorithm')"
      :text="$i18n.t('Algorithm of the generated key pair.')"
    />

    <form-group-key-spec namespace="key_spec"
      :column-label="$i18n.t('Key Specification')"
      :text="$i18n.t('Key size (RSA, e.g. 2048) or curve name (ECDSA, e.g. secp256r1).')"
    />

    <form-group-revocation-reason namespace="revocation_reason"
      :column-label="$i18n.t('Revocation Reason')"
      :text="$i18n.t('Reason used when revoking the certificate.')"
    />

    <form-group-country namespace="country"
      :column-label="$i18n.t('Country')"
      :text="$i18n.t('Country for the certificate.')"
    />

    <form-group-state namespace="state"
      :column-label="$i18n.t('State')"
      :text="$i18n.t('State for the certificate.')"
    />

    <form-group-locality namespace="locality"
      :column-label="$i18n.t('Locality')"
      :text="$i18n.t('Locality for the certificate.')"
    />

    <form-group-organization namespace="organization"
      :column-label="$i18n.t('Organization')"
      :text="$i18n.t('Organization for the certificate.')"
    />

    <form-group-common-name-attribute namespace="cn_attribute"
      :column-label="$i18n.t('Common Name Attribute')"
      :text="$i18n.t('Defines what attribute of the node to use as the common name during the certificate generation.')"
    />

    <form-group-common-name-format namespace="cn_format"
      :column-label="$i18n.t('Common Name Format')"
      :text="$i18n.t('Defines how the common name will be formated. %s will expand to the defined Common Name Attribute value.')"
    />

    <form-group-revoke-on-registration namespace="revoke_on_unregistration"
      :column-label="$i18n.t('Revoke on unregistration')"
      enabled-value="Y"
      disabled-value="N"
      :text="$i18n.t('Enable to revoke the certificate when the node using it is unregistered. Do not use if multiple devices share the same certificate.')"
    />

    <form-group-certificate-validity-time-from-unreg-date namespace="certificate_validity_time_from_unreg_date"
      :column-label="$i18n.t('Set the certificate validity date to the unreg date value')"
      enabled-value="Y"
      disabled-value="N"
      :text="$i18n.t('Enable to apply the same expiration date of the certificate as the unregistration date of the node.')"
    />

    <form-group-ca-cert-path namespace="ca_cert_path"
      :column-label="$i18n.t('CA certificate file')"
      :title="$i18n.t('Upload CA certificate file')"
      :text="$i18n.t('CA certificate that issues the client certificates.')"
    />

    <form-group-server-cert-path namespace="server_cert_path"
      :column-label="$i18n.t('Server certificate file')"
      :title="$i18n.t('Upload server certificate file')"
      :text="$i18n.t('RADIUS server authentication certificate.')"
    />
  </base-form>
</template>
<script>
import { BaseForm } from '@/components/new/'
import {
  FormGroupApiCaPath,
  FormGroupCaCertPath,
  FormGroupCaName,
  FormGroupCertificateProfile,
  FormGroupCertificateValidityTimeFromUnregDate,
  FormGroupClientCertPath,
  FormGroupClientKeyPath,
  FormGroupCommonNameAttribute,
  FormGroupCommonNameFormat,
  FormGroupCountry,
  FormGroupEndEntityProfile,
  FormGroupHost,
  FormGroupIdentifier,
  FormGroupKeyAlgorithm,
  FormGroupKeySpec,
  FormGroupLocality,
  FormGroupOrganization,
  FormGroupPort,
  FormGroupProto,
  FormGroupRevocationReason,
  FormGroupRevokeOnRegistration,
  FormGroupServerCertPath,
  FormGroupState
} from './'
import { useForm as setup, useFormProps as props } from '../_composables/useForm'

const components = {
  BaseForm,

  FormGroupApiCaPath,
  FormGroupCaCertPath,
  FormGroupCaName,
  FormGroupCertificateProfile,
  FormGroupCertificateValidityTimeFromUnregDate,
  FormGroupClientCertPath,
  FormGroupClientKeyPath,
  FormGroupCommonNameAttribute,
  FormGroupCommonNameFormat,
  FormGroupCountry,
  FormGroupEndEntityProfile,
  FormGroupHost,
  FormGroupIdentifier,
  FormGroupKeyAlgorithm,
  FormGroupKeySpec,
  FormGroupLocality,
  FormGroupOrganization,
  FormGroupPort,
  FormGroupProto,
  FormGroupRevocationReason,
  FormGroupRevokeOnRegistration,
  FormGroupServerCertPath,
  FormGroupState
}

// @vue/component
export default {
  name: 'form-type-ejbca',
  inheritAttrs: false,
  components,
  props,
  setup
}
</script>
