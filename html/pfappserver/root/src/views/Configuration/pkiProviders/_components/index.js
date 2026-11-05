import { BaseViewCollectionItem } from '../../_components/new/'
import {
  BaseFormButtonBar,
  BaseFormGroupChosenCountry,
  BaseFormGroupChosenOne,
  BaseFormGroupFileUpload,
  BaseFormGroupInput,
  BaseFormGroupInputPassword,
  BaseFormGroupSwitch,
} from '@/components/new/'
import {
  BaseFormGroupChosenOneProfile
} from '../../pki/_components/'
import TheForm from './TheForm'
import TheView from './TheView'

export {
  BaseViewCollectionItem        as BaseView,
  BaseFormButtonBar             as FormButtonBar,

  BaseFormGroupFileUpload       as FormGroupApiCaPath,
  BaseFormGroupInput            as FormGroupCaName,
  BaseFormGroupInput            as FormGroupCertificateProfile,
  BaseFormGroupInput            as FormGroupEndEntityProfile,
  BaseFormGroupInput            as FormGroupHost,
  BaseFormGroupChosenOne        as FormGroupKeyAlgorithm,
  BaseFormGroupInput            as FormGroupKeySpec,
  BaseFormGroupInput            as FormGroupPort,
  BaseFormGroupChosenOne        as FormGroupProto,
  BaseFormGroupChosenOne        as FormGroupRevocationReason,
  BaseFormGroupFileUpload       as FormGroupCaCertPath,
  BaseFormGroupFileUpload       as FormGroupClientCertPath,
  BaseFormGroupFileUpload       as FormGroupClientKeyPath,
  BaseFormGroupChosenOne        as FormGroupCommonNameAttribute,
  BaseFormGroupInput            as FormGroupCommonNameFormat,
  BaseFormGroupChosenCountry    as FormGroupCountry,
  BaseFormGroupInput            as FormGroupIdentifier,
  BaseFormGroupInput            as FormGroupLocality,
  BaseFormGroupInput            as FormGroupOrganization,
  BaseFormGroupInput            as FormGroupOrganizationalUnit,
  BaseFormGroupInputPassword    as FormGroupPassword,
  BaseFormGroupInput            as FormGroupPostalCode,
  BaseFormGroupChosenOneProfile as FormGroupProfile,
  BaseFormGroupSwitch           as FormGroupRevokeOnRegistration,
  BaseFormGroupSwitch           as FormGroupCertificateValidityTimeFromUnregDate,
  BaseFormGroupFileUpload       as FormGroupServerCertPath,
  BaseFormGroupInput            as FormGroupState,
  BaseFormGroupInput            as FormGroupStreetAddress,
  BaseFormGroupInput            as FormGroupUrl,
  BaseFormGroupInput            as FormGroupUsername,

  TheForm,
  TheView
}
