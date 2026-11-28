import { useTranslation } from "react-i18next";
import { TextControl } from "@keycloak/keycloak-ui-shared";
import { convertAttributeNameToForm } from "../../util";

export const X509 = () => {
  const { t } = useTranslation();
  return (
    <>
      <TextControl
        name={convertAttributeNameToForm("attributes.x509.subjectdn")}
        label={t("subject")}
        labelIcon={t("subjectHelp")}
        rules={{
          required: t("required"),
        }}
      />
      <TextControl
        name={convertAttributeNameToForm("attributes.x509.casubjectdn")}
        label={t("casubject")}
        labelIcon={t("casubjectHelp")}
        rules={{
          required: t("required"),
        }}
      />
    </>
  );
};
