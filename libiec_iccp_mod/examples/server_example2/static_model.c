/*
 * static_model.c
 *
 * automatically generated from complexModel.scd
 */
#include <stdlib.h>
#include "model.h"

extern IedModel iedModel;
static void initializeValues();
extern LogicalDevice iedModel_Inverter;
extern LogicalNode   iedModel_Inverter_LLN0;
extern DataObject    iedModel_Inverter_LLN0_Mod;
extern DataAttribute iedModel_Inverter_LLN0_Mod_q;
extern DataAttribute iedModel_Inverter_LLN0_Mod_t;
extern DataAttribute iedModel_Inverter_LLN0_Mod_ctlModel;
extern DataObject    iedModel_Inverter_LLN0_Beh;
extern DataAttribute iedModel_Inverter_LLN0_Beh_stVal;
extern DataAttribute iedModel_Inverter_LLN0_Beh_q;
extern DataAttribute iedModel_Inverter_LLN0_Beh_t;
extern DataObject    iedModel_Inverter_LLN0_Health;
extern DataAttribute iedModel_Inverter_LLN0_Health_stVal;
extern DataAttribute iedModel_Inverter_LLN0_Health_q;
extern DataAttribute iedModel_Inverter_LLN0_Health_t;
extern DataObject    iedModel_Inverter_LLN0_NamPlt;
extern DataAttribute iedModel_Inverter_LLN0_NamPlt_vendor;
extern DataAttribute iedModel_Inverter_LLN0_NamPlt_swRev;
extern DataAttribute iedModel_Inverter_LLN0_NamPlt_d;
extern DataAttribute iedModel_Inverter_LLN0_NamPlt_configRev;
extern DataAttribute iedModel_Inverter_LLN0_NamPlt_ldNs;
extern LogicalNode   iedModel_Inverter_LPHD1;
extern DataObject    iedModel_Inverter_LPHD1_PhyNam;
extern DataAttribute iedModel_Inverter_LPHD1_PhyNam_vendor;
extern DataObject    iedModel_Inverter_LPHD1_PhyHealth;
extern DataAttribute iedModel_Inverter_LPHD1_PhyHealth_stVal;
extern DataAttribute iedModel_Inverter_LPHD1_PhyHealth_q;
extern DataAttribute iedModel_Inverter_LPHD1_PhyHealth_t;
extern DataObject    iedModel_Inverter_LPHD1_Proxy;
extern DataAttribute iedModel_Inverter_LPHD1_Proxy_stVal;
extern DataAttribute iedModel_Inverter_LPHD1_Proxy_q;
extern DataAttribute iedModel_Inverter_LPHD1_Proxy_t;
extern LogicalNode   iedModel_Inverter_ZINV1;
extern DataObject    iedModel_Inverter_ZINV1_Mod;
extern DataAttribute iedModel_Inverter_ZINV1_Mod_q;
extern DataAttribute iedModel_Inverter_ZINV1_Mod_t;
extern DataAttribute iedModel_Inverter_ZINV1_Mod_ctlModel;
extern DataObject    iedModel_Inverter_ZINV1_Beh;
extern DataAttribute iedModel_Inverter_ZINV1_Beh_stVal;
extern DataAttribute iedModel_Inverter_ZINV1_Beh_q;
extern DataAttribute iedModel_Inverter_ZINV1_Beh_t;
extern DataObject    iedModel_Inverter_ZINV1_Health;
extern DataAttribute iedModel_Inverter_ZINV1_Health_stVal;
extern DataAttribute iedModel_Inverter_ZINV1_Health_q;
extern DataAttribute iedModel_Inverter_ZINV1_Health_t;
extern DataObject    iedModel_Inverter_ZINV1_NamPlt;
extern DataAttribute iedModel_Inverter_ZINV1_NamPlt_vendor;
extern DataAttribute iedModel_Inverter_ZINV1_NamPlt_swRev;
extern DataAttribute iedModel_Inverter_ZINV1_NamPlt_d;
extern DataObject    iedModel_Inverter_ZINV1_WRtg;
extern DataAttribute iedModel_Inverter_ZINV1_WRtg_setMag;
extern DataAttribute iedModel_Inverter_ZINV1_WRtg_setMag_f;
extern DataAttribute iedModel_Inverter_ZINV1_WRtg_units;
extern DataAttribute iedModel_Inverter_ZINV1_WRtg_units_SIUnit;
extern DataObject    iedModel_Inverter_ZINV1_VarRtg;
extern DataAttribute iedModel_Inverter_ZINV1_VarRtg_setMag;
extern DataAttribute iedModel_Inverter_ZINV1_VarRtg_setMag_f;
extern DataAttribute iedModel_Inverter_ZINV1_VarRtg_units;
extern DataAttribute iedModel_Inverter_ZINV1_VarRtg_units_SIUnit;
extern DataObject    iedModel_Inverter_ZINV1_ACTyp;
extern DataAttribute iedModel_Inverter_ZINV1_ACTyp_setVal;
extern DataObject    iedModel_Inverter_ZINV1_OutWSet;
extern DataAttribute iedModel_Inverter_ZINV1_OutWSet_setMag;
extern DataAttribute iedModel_Inverter_ZINV1_OutWSet_setMag_f;
extern DataAttribute iedModel_Inverter_ZINV1_OutWSet_units;
extern DataAttribute iedModel_Inverter_ZINV1_OutWSet_units_SIUnit;
extern DataObject    iedModel_Inverter_ZINV1_OutVarSet;
extern DataAttribute iedModel_Inverter_ZINV1_OutVarSet_setMag;
extern DataAttribute iedModel_Inverter_ZINV1_OutVarSet_setMag_f;
extern DataAttribute iedModel_Inverter_ZINV1_OutVarSet_units;
extern DataAttribute iedModel_Inverter_ZINV1_OutVarSet_units_SIUnit;
extern LogicalNode   iedModel_Inverter_MMXU1;
extern DataObject    iedModel_Inverter_MMXU1_Mod;
extern DataAttribute iedModel_Inverter_MMXU1_Mod_q;
extern DataAttribute iedModel_Inverter_MMXU1_Mod_t;
extern DataAttribute iedModel_Inverter_MMXU1_Mod_ctlModel;
extern DataObject    iedModel_Inverter_MMXU1_Beh;
extern DataAttribute iedModel_Inverter_MMXU1_Beh_stVal;
extern DataAttribute iedModel_Inverter_MMXU1_Beh_q;
extern DataAttribute iedModel_Inverter_MMXU1_Beh_t;
extern DataObject    iedModel_Inverter_MMXU1_Health;
extern DataAttribute iedModel_Inverter_MMXU1_Health_stVal;
extern DataAttribute iedModel_Inverter_MMXU1_Health_q;
extern DataAttribute iedModel_Inverter_MMXU1_Health_t;
extern DataObject    iedModel_Inverter_MMXU1_NamPlt;
extern DataAttribute iedModel_Inverter_MMXU1_NamPlt_vendor;
extern DataAttribute iedModel_Inverter_MMXU1_NamPlt_swRev;
extern DataAttribute iedModel_Inverter_MMXU1_NamPlt_d;
extern DataObject    iedModel_Inverter_MMXU1_TotW;
extern DataAttribute iedModel_Inverter_MMXU1_TotW_mag;
extern DataAttribute iedModel_Inverter_MMXU1_TotW_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_TotW_q;
extern DataAttribute iedModel_Inverter_MMXU1_TotW_t;
extern DataObject    iedModel_Inverter_MMXU1_TotVAr;
extern DataAttribute iedModel_Inverter_MMXU1_TotVAr_mag;
extern DataAttribute iedModel_Inverter_MMXU1_TotVAr_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_TotVAr_q;
extern DataAttribute iedModel_Inverter_MMXU1_TotVAr_t;
extern DataObject    iedModel_Inverter_MMXU1_TotVA;
extern DataAttribute iedModel_Inverter_MMXU1_TotVA_mag;
extern DataAttribute iedModel_Inverter_MMXU1_TotVA_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_TotVA_q;
extern DataAttribute iedModel_Inverter_MMXU1_TotVA_t;
extern DataObject    iedModel_Inverter_MMXU1_Hz;
extern DataAttribute iedModel_Inverter_MMXU1_Hz_mag;
extern DataAttribute iedModel_Inverter_MMXU1_Hz_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_Hz_q;
extern DataAttribute iedModel_Inverter_MMXU1_Hz_t;
extern DataObject    iedModel_Inverter_MMXU1_PhV;
extern DataObject    iedModel_Inverter_MMXU1_PhV_phsA;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_q;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_t;
extern DataObject    iedModel_Inverter_MMXU1_PhV_phsB;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_q;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_t;
extern DataObject    iedModel_Inverter_MMXU1_PhV_phsC;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_q;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_t;
extern DataObject    iedModel_Inverter_MMXU1_PhV_neut;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_neut_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_neut_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_neut_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_neut_q;
extern DataAttribute iedModel_Inverter_MMXU1_PhV_neut_t;
extern DataObject    iedModel_Inverter_MMXU1_A;
extern DataObject    iedModel_Inverter_MMXU1_A_phsA;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsA_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsA_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsA_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsA_q;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsA_t;
extern DataObject    iedModel_Inverter_MMXU1_A_phsB;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsB_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsB_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsB_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsB_q;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsB_t;
extern DataObject    iedModel_Inverter_MMXU1_A_phsC;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsC_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsC_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsC_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsC_q;
extern DataAttribute iedModel_Inverter_MMXU1_A_phsC_t;
extern DataObject    iedModel_Inverter_MMXU1_A_neut;
extern DataAttribute iedModel_Inverter_MMXU1_A_neut_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_A_neut_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_A_neut_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_A_neut_q;
extern DataAttribute iedModel_Inverter_MMXU1_A_neut_t;
extern DataObject    iedModel_Inverter_MMXU1_W;
extern DataObject    iedModel_Inverter_MMXU1_W_phsA;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsA_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsA_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsA_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsA_q;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsA_t;
extern DataObject    iedModel_Inverter_MMXU1_W_phsB;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsB_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsB_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsB_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsB_q;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsB_t;
extern DataObject    iedModel_Inverter_MMXU1_W_phsC;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsC_cVal;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsC_cVal_mag;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsC_cVal_mag_f;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsC_q;
extern DataAttribute iedModel_Inverter_MMXU1_W_phsC_t;
extern LogicalDevice iedModel_Battery;
extern LogicalNode   iedModel_Battery_LLN0;
extern DataObject    iedModel_Battery_LLN0_Mod;
extern DataAttribute iedModel_Battery_LLN0_Mod_q;
extern DataAttribute iedModel_Battery_LLN0_Mod_t;
extern DataAttribute iedModel_Battery_LLN0_Mod_ctlModel;
extern DataObject    iedModel_Battery_LLN0_Beh;
extern DataAttribute iedModel_Battery_LLN0_Beh_stVal;
extern DataAttribute iedModel_Battery_LLN0_Beh_q;
extern DataAttribute iedModel_Battery_LLN0_Beh_t;
extern DataObject    iedModel_Battery_LLN0_Health;
extern DataAttribute iedModel_Battery_LLN0_Health_stVal;
extern DataAttribute iedModel_Battery_LLN0_Health_q;
extern DataAttribute iedModel_Battery_LLN0_Health_t;
extern DataObject    iedModel_Battery_LLN0_NamPlt;
extern DataAttribute iedModel_Battery_LLN0_NamPlt_vendor;
extern DataAttribute iedModel_Battery_LLN0_NamPlt_swRev;
extern DataAttribute iedModel_Battery_LLN0_NamPlt_d;
extern DataAttribute iedModel_Battery_LLN0_NamPlt_configRev;
extern DataAttribute iedModel_Battery_LLN0_NamPlt_ldNs;
extern LogicalNode   iedModel_Battery_LPHD1;
extern DataObject    iedModel_Battery_LPHD1_PhyNam;
extern DataAttribute iedModel_Battery_LPHD1_PhyNam_vendor;
extern DataObject    iedModel_Battery_LPHD1_PhyHealth;
extern DataAttribute iedModel_Battery_LPHD1_PhyHealth_stVal;
extern DataAttribute iedModel_Battery_LPHD1_PhyHealth_q;
extern DataAttribute iedModel_Battery_LPHD1_PhyHealth_t;
extern DataObject    iedModel_Battery_LPHD1_Proxy;
extern DataAttribute iedModel_Battery_LPHD1_Proxy_stVal;
extern DataAttribute iedModel_Battery_LPHD1_Proxy_q;
extern DataAttribute iedModel_Battery_LPHD1_Proxy_t;
extern LogicalNode   iedModel_Battery_ZBAT1;
extern DataObject    iedModel_Battery_ZBAT1_Mod;
extern DataAttribute iedModel_Battery_ZBAT1_Mod_q;
extern DataAttribute iedModel_Battery_ZBAT1_Mod_t;
extern DataAttribute iedModel_Battery_ZBAT1_Mod_ctlModel;
extern DataObject    iedModel_Battery_ZBAT1_Beh;
extern DataAttribute iedModel_Battery_ZBAT1_Beh_stVal;
extern DataAttribute iedModel_Battery_ZBAT1_Beh_q;
extern DataAttribute iedModel_Battery_ZBAT1_Beh_t;
extern DataObject    iedModel_Battery_ZBAT1_Health;
extern DataAttribute iedModel_Battery_ZBAT1_Health_stVal;
extern DataAttribute iedModel_Battery_ZBAT1_Health_q;
extern DataAttribute iedModel_Battery_ZBAT1_Health_t;
extern DataObject    iedModel_Battery_ZBAT1_NamPlt;
extern DataAttribute iedModel_Battery_ZBAT1_NamPlt_vendor;
extern DataAttribute iedModel_Battery_ZBAT1_NamPlt_swRev;
extern DataAttribute iedModel_Battery_ZBAT1_NamPlt_d;
extern DataObject    iedModel_Battery_ZBAT1_Vol;
extern DataAttribute iedModel_Battery_ZBAT1_Vol_mag;
extern DataAttribute iedModel_Battery_ZBAT1_Vol_mag_f;
extern DataAttribute iedModel_Battery_ZBAT1_Vol_q;
extern DataAttribute iedModel_Battery_ZBAT1_Vol_t;
extern DataObject    iedModel_Battery_ZBAT1_Amp;
extern DataAttribute iedModel_Battery_ZBAT1_Amp_mag;
extern DataAttribute iedModel_Battery_ZBAT1_Amp_mag_f;
extern DataAttribute iedModel_Battery_ZBAT1_Amp_q;
extern DataAttribute iedModel_Battery_ZBAT1_Amp_t;
extern LogicalNode   iedModel_Battery_ZBTC1;
extern DataObject    iedModel_Battery_ZBTC1_Mod;
extern DataAttribute iedModel_Battery_ZBTC1_Mod_q;
extern DataAttribute iedModel_Battery_ZBTC1_Mod_t;
extern DataAttribute iedModel_Battery_ZBTC1_Mod_ctlModel;
extern DataObject    iedModel_Battery_ZBTC1_Beh;
extern DataAttribute iedModel_Battery_ZBTC1_Beh_stVal;
extern DataAttribute iedModel_Battery_ZBTC1_Beh_q;
extern DataAttribute iedModel_Battery_ZBTC1_Beh_t;
extern DataObject    iedModel_Battery_ZBTC1_Health;
extern DataAttribute iedModel_Battery_ZBTC1_Health_stVal;
extern DataAttribute iedModel_Battery_ZBTC1_Health_q;
extern DataAttribute iedModel_Battery_ZBTC1_Health_t;
extern DataObject    iedModel_Battery_ZBTC1_NamPlt;
extern DataAttribute iedModel_Battery_ZBTC1_NamPlt_vendor;
extern DataAttribute iedModel_Battery_ZBTC1_NamPlt_swRev;
extern DataAttribute iedModel_Battery_ZBTC1_NamPlt_d;
extern DataObject    iedModel_Battery_ZBTC1_BatChaSt;
extern DataObject    iedModel_Battery_ZBTC1_BatChaPwr;
extern DataObject    iedModel_Battery_ZBTC1_BatChaMod;
extern DataObject    iedModel_Battery_ZBTC1_ChaV;
extern DataAttribute iedModel_Battery_ZBTC1_ChaV_mag;
extern DataAttribute iedModel_Battery_ZBTC1_ChaV_mag_f;
extern DataAttribute iedModel_Battery_ZBTC1_ChaV_q;
extern DataAttribute iedModel_Battery_ZBTC1_ChaV_t;
extern DataObject    iedModel_Battery_ZBTC1_ChaA;
extern DataAttribute iedModel_Battery_ZBTC1_ChaA_mag;
extern DataAttribute iedModel_Battery_ZBTC1_ChaA_mag_f;
extern DataAttribute iedModel_Battery_ZBTC1_ChaA_q;
extern DataAttribute iedModel_Battery_ZBTC1_ChaA_t;
extern LogicalDevice iedModel_Physical_Measurements;
extern LogicalNode   iedModel_Physical_Measurements_LLN0;
extern DataObject    iedModel_Physical_Measurements_LLN0_Mod;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Mod_q;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Mod_t;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Mod_ctlModel;
extern DataObject    iedModel_Physical_Measurements_LLN0_Beh;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Beh_stVal;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Beh_q;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Beh_t;
extern DataObject    iedModel_Physical_Measurements_LLN0_Health;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Health_stVal;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Health_q;
extern DataAttribute iedModel_Physical_Measurements_LLN0_Health_t;
extern DataObject    iedModel_Physical_Measurements_LLN0_NamPlt;
extern DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_vendor;
extern DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_swRev;
extern DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_d;
extern DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_configRev;
extern DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_ldNs;
extern LogicalNode   iedModel_Physical_Measurements_LPHD1;
extern DataObject    iedModel_Physical_Measurements_LPHD1_PhyNam;
extern DataAttribute iedModel_Physical_Measurements_LPHD1_PhyNam_vendor;
extern DataObject    iedModel_Physical_Measurements_LPHD1_PhyHealth;
extern DataAttribute iedModel_Physical_Measurements_LPHD1_PhyHealth_stVal;
extern DataAttribute iedModel_Physical_Measurements_LPHD1_PhyHealth_q;
extern DataAttribute iedModel_Physical_Measurements_LPHD1_PhyHealth_t;
extern DataObject    iedModel_Physical_Measurements_LPHD1_Proxy;
extern DataAttribute iedModel_Physical_Measurements_LPHD1_Proxy_stVal;
extern DataAttribute iedModel_Physical_Measurements_LPHD1_Proxy_q;
extern DataAttribute iedModel_Physical_Measurements_LPHD1_Proxy_t;

extern DataSet ds_Inverter_LLN0_dataset1;


extern DataSetEntry ds_Inverter_LLN0_dataset1_fcda0;
extern DataSetEntry ds_Inverter_LLN0_dataset1_fcda1;
extern DataSetEntry ds_Inverter_LLN0_dataset1_fcda2;
extern DataSetEntry ds_Inverter_LLN0_dataset1_fcda3;
extern DataSetEntry ds_Inverter_LLN0_dataset1_fcda4;

DataSetEntry ds_Inverter_LLN0_dataset1_fcda0 = {
  "ied1Inverter",
  "LLN0$ST$Mod$q",
  -1,
  NULL,
  NULL,
  &ds_Inverter_LLN0_dataset1_fcda1
};

DataSetEntry ds_Inverter_LLN0_dataset1_fcda1 = {
  "ied1Battery",
  "LLN0$ST$Mod$q",
  -1,
  NULL,
  NULL,
  &ds_Inverter_LLN0_dataset1_fcda2
};

DataSetEntry ds_Inverter_LLN0_dataset1_fcda2 = {
  "ied1Inverter",
  "MMXU1$ST$Mod$q",
  -1,
  NULL,
  NULL,
  &ds_Inverter_LLN0_dataset1_fcda3
};

DataSetEntry ds_Inverter_LLN0_dataset1_fcda3 = {
  "ied1Inverter",
  "MMXU1$CF$Mod$ctlModel",
  -1,
  NULL,
  NULL,
  &ds_Inverter_LLN0_dataset1_fcda4
};

DataSetEntry ds_Inverter_LLN0_dataset1_fcda4 = {
  "ied1Inverter",
  "MMXU1$MX$TotW$mag",
  -1,
  NULL,
  NULL,
  NULL
};

DataSet ds_Inverter_LLN0_dataset1 = {
  "ied1Inverter",
  "LLN0$dataset1",
  5,
  &ds_Inverter_LLN0_dataset1_fcda0,
  NULL
};

LogicalDevice iedModel_Inverter = {
    LogicalDeviceModelType,
    "ied1Inverter",
    (ModelNode*) &iedModel,
    (ModelNode*) &iedModel_Battery,
    (ModelNode*) &iedModel_Inverter_LLN0
};

LogicalNode iedModel_Inverter_LLN0 = {
    LogicalNodeModelType,
    "LLN0",
    (ModelNode*) &iedModel_Inverter,
    (ModelNode*) &iedModel_Inverter_LPHD1,
    (ModelNode*) &iedModel_Inverter_LLN0_Mod,
};

DataObject iedModel_Inverter_LLN0_Mod = {
    DataObjectModelType,
    "Mod",
    (ModelNode*) &iedModel_Inverter_LLN0,
    (ModelNode*) &iedModel_Inverter_LLN0_Beh,
    (ModelNode*) &iedModel_Inverter_LLN0_Mod_q,
    0
};

DataAttribute iedModel_Inverter_LLN0_Mod_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_LLN0_Mod,
    (ModelNode*) &iedModel_Inverter_LLN0_Mod_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_Mod_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_LLN0_Mod,
    (ModelNode*) &iedModel_Inverter_LLN0_Mod_ctlModel,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_Mod_ctlModel = {
    DataAttributeModelType,
    "ctlModel",
    (ModelNode*) &iedModel_Inverter_LLN0_Mod,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_LLN0_Beh = {
    DataObjectModelType,
    "Beh",
    (ModelNode*) &iedModel_Inverter_LLN0,
    (ModelNode*) &iedModel_Inverter_LLN0_Health,
    (ModelNode*) &iedModel_Inverter_LLN0_Beh_stVal,
    0
};

DataAttribute iedModel_Inverter_LLN0_Beh_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Inverter_LLN0_Beh,
    (ModelNode*) &iedModel_Inverter_LLN0_Beh_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_Beh_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_LLN0_Beh,
    (ModelNode*) &iedModel_Inverter_LLN0_Beh_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_Beh_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_LLN0_Beh,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_LLN0_Health = {
    DataObjectModelType,
    "Health",
    (ModelNode*) &iedModel_Inverter_LLN0,
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt,
    (ModelNode*) &iedModel_Inverter_LLN0_Health_stVal,
    0
};

DataAttribute iedModel_Inverter_LLN0_Health_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Inverter_LLN0_Health,
    (ModelNode*) &iedModel_Inverter_LLN0_Health_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_Health_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_LLN0_Health,
    (ModelNode*) &iedModel_Inverter_LLN0_Health_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_Health_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_LLN0_Health,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_LLN0_NamPlt = {
    DataObjectModelType,
    "NamPlt",
    (ModelNode*) &iedModel_Inverter_LLN0,
    NULL,
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt_vendor,
    0
};

DataAttribute iedModel_Inverter_LLN0_NamPlt_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt,
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt_swRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_NamPlt_swRev = {
    DataAttributeModelType,
    "swRev",
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt,
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt_d,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_NamPlt_d = {
    DataAttributeModelType,
    "d",
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt,
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt_configRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_NamPlt_configRev = {
    DataAttributeModelType,
    "configRev",
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt,
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt_ldNs,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_LLN0_NamPlt_ldNs = {
    DataAttributeModelType,
    "ldNs",
    (ModelNode*) &iedModel_Inverter_LLN0_NamPlt,
    NULL,
    NULL,
    0,
    EX,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

LogicalNode iedModel_Inverter_LPHD1 = {
    LogicalNodeModelType,
    "LPHD1",
    (ModelNode*) &iedModel_Inverter,
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyNam,
};

DataObject iedModel_Inverter_LPHD1_PhyNam = {
    DataObjectModelType,
    "PhyNam",
    (ModelNode*) &iedModel_Inverter_LPHD1,
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyNam_vendor,
    0
};

DataAttribute iedModel_Inverter_LPHD1_PhyNam_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyNam,
    NULL,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_LPHD1_PhyHealth = {
    DataObjectModelType,
    "PhyHealth",
    (ModelNode*) &iedModel_Inverter_LPHD1,
    (ModelNode*) &iedModel_Inverter_LPHD1_Proxy,
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyHealth_stVal,
    0
};

DataAttribute iedModel_Inverter_LPHD1_PhyHealth_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyHealth_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LPHD1_PhyHealth_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyHealth_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LPHD1_PhyHealth_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_LPHD1_PhyHealth,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_LPHD1_Proxy = {
    DataObjectModelType,
    "Proxy",
    (ModelNode*) &iedModel_Inverter_LPHD1,
    NULL,
    (ModelNode*) &iedModel_Inverter_LPHD1_Proxy_stVal,
    0
};

DataAttribute iedModel_Inverter_LPHD1_Proxy_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Inverter_LPHD1_Proxy,
    (ModelNode*) &iedModel_Inverter_LPHD1_Proxy_q,
    NULL,
    0,
    ST,
    BOOLEAN,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LPHD1_Proxy_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_LPHD1_Proxy,
    (ModelNode*) &iedModel_Inverter_LPHD1_Proxy_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_LPHD1_Proxy_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_LPHD1_Proxy,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

LogicalNode iedModel_Inverter_ZINV1 = {
    LogicalNodeModelType,
    "ZINV1",
    (ModelNode*) &iedModel_Inverter,
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_ZINV1_Mod,
};

DataObject iedModel_Inverter_ZINV1_Mod = {
    DataObjectModelType,
    "Mod",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_ZINV1_Beh,
    (ModelNode*) &iedModel_Inverter_ZINV1_Mod_q,
    0
};

DataAttribute iedModel_Inverter_ZINV1_Mod_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_ZINV1_Mod,
    (ModelNode*) &iedModel_Inverter_ZINV1_Mod_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_Mod_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_ZINV1_Mod,
    (ModelNode*) &iedModel_Inverter_ZINV1_Mod_ctlModel,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_Mod_ctlModel = {
    DataAttributeModelType,
    "ctlModel",
    (ModelNode*) &iedModel_Inverter_ZINV1_Mod,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_ZINV1_Beh = {
    DataObjectModelType,
    "Beh",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_ZINV1_Health,
    (ModelNode*) &iedModel_Inverter_ZINV1_Beh_stVal,
    0
};

DataAttribute iedModel_Inverter_ZINV1_Beh_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Inverter_ZINV1_Beh,
    (ModelNode*) &iedModel_Inverter_ZINV1_Beh_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_Beh_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_ZINV1_Beh,
    (ModelNode*) &iedModel_Inverter_ZINV1_Beh_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_Beh_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_ZINV1_Beh,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_ZINV1_Health = {
    DataObjectModelType,
    "Health",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_ZINV1_NamPlt,
    (ModelNode*) &iedModel_Inverter_ZINV1_Health_stVal,
    0
};

DataAttribute iedModel_Inverter_ZINV1_Health_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Inverter_ZINV1_Health,
    (ModelNode*) &iedModel_Inverter_ZINV1_Health_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_Health_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_ZINV1_Health,
    (ModelNode*) &iedModel_Inverter_ZINV1_Health_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_Health_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_ZINV1_Health,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_ZINV1_NamPlt = {
    DataObjectModelType,
    "NamPlt",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg,
    (ModelNode*) &iedModel_Inverter_ZINV1_NamPlt_vendor,
    0
};

DataAttribute iedModel_Inverter_ZINV1_NamPlt_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Inverter_ZINV1_NamPlt,
    (ModelNode*) &iedModel_Inverter_ZINV1_NamPlt_swRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_NamPlt_swRev = {
    DataAttributeModelType,
    "swRev",
    (ModelNode*) &iedModel_Inverter_ZINV1_NamPlt,
    (ModelNode*) &iedModel_Inverter_ZINV1_NamPlt_d,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_NamPlt_d = {
    DataAttributeModelType,
    "d",
    (ModelNode*) &iedModel_Inverter_ZINV1_NamPlt,
    NULL,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_ZINV1_WRtg = {
    DataObjectModelType,
    "WRtg",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg,
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg_setMag,
    0
};

DataAttribute iedModel_Inverter_ZINV1_WRtg_setMag = {
    DataAttributeModelType,
    "setMag",
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg,
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg_units,
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg_setMag_f,
    0,
    SP,
    CONSTRUCTED,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_WRtg_setMag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg_setMag,
    NULL,
    NULL,
    0,
    SP,
    FLOAT32,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_WRtg_units = {
    DataAttributeModelType,
    "units",
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg,
    NULL,
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg_units_SIUnit,
    0,
    CF,
    CONSTRUCTED,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_WRtg_units_SIUnit = {
    DataAttributeModelType,
    "SIUnit",
    (ModelNode*) &iedModel_Inverter_ZINV1_WRtg_units,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_ZINV1_VarRtg = {
    DataObjectModelType,
    "VarRtg",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_ZINV1_ACTyp,
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg_setMag,
    0
};

DataAttribute iedModel_Inverter_ZINV1_VarRtg_setMag = {
    DataAttributeModelType,
    "setMag",
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg,
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg_units,
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg_setMag_f,
    0,
    SP,
    CONSTRUCTED,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_VarRtg_setMag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg_setMag,
    NULL,
    NULL,
    0,
    SP,
    FLOAT32,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_VarRtg_units = {
    DataAttributeModelType,
    "units",
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg,
    NULL,
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg_units_SIUnit,
    0,
    CF,
    CONSTRUCTED,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_VarRtg_units_SIUnit = {
    DataAttributeModelType,
    "SIUnit",
    (ModelNode*) &iedModel_Inverter_ZINV1_VarRtg_units,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_ZINV1_ACTyp = {
    DataObjectModelType,
    "ACTyp",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet,
    (ModelNode*) &iedModel_Inverter_ZINV1_ACTyp_setVal,
    0
};

DataAttribute iedModel_Inverter_ZINV1_ACTyp_setVal = {
    DataAttributeModelType,
    "setVal",
    (ModelNode*) &iedModel_Inverter_ZINV1_ACTyp,
    NULL,
    NULL,
    0,
    SP,
    INT32,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_ZINV1_OutWSet = {
    DataObjectModelType,
    "OutWSet",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet_setMag,
    0
};

DataAttribute iedModel_Inverter_ZINV1_OutWSet_setMag = {
    DataAttributeModelType,
    "setMag",
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet_units,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet_setMag_f,
    0,
    SP,
    CONSTRUCTED,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_OutWSet_setMag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet_setMag,
    NULL,
    NULL,
    0,
    SP,
    FLOAT32,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_OutWSet_units = {
    DataAttributeModelType,
    "units",
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet,
    NULL,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet_units_SIUnit,
    0,
    CF,
    CONSTRUCTED,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_OutWSet_units_SIUnit = {
    DataAttributeModelType,
    "SIUnit",
    (ModelNode*) &iedModel_Inverter_ZINV1_OutWSet_units,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_ZINV1_OutVarSet = {
    DataObjectModelType,
    "OutVarSet",
    (ModelNode*) &iedModel_Inverter_ZINV1,
    NULL,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet_setMag,
    0
};

DataAttribute iedModel_Inverter_ZINV1_OutVarSet_setMag = {
    DataAttributeModelType,
    "setMag",
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet_units,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet_setMag_f,
    0,
    SP,
    CONSTRUCTED,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_OutVarSet_setMag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet_setMag,
    NULL,
    NULL,
    0,
    SP,
    FLOAT32,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_OutVarSet_units = {
    DataAttributeModelType,
    "units",
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet,
    NULL,
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet_units_SIUnit,
    0,
    CF,
    CONSTRUCTED,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_ZINV1_OutVarSet_units_SIUnit = {
    DataAttributeModelType,
    "SIUnit",
    (ModelNode*) &iedModel_Inverter_ZINV1_OutVarSet_units,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

LogicalNode iedModel_Inverter_MMXU1 = {
    LogicalNodeModelType,
    "MMXU1",
    (ModelNode*) &iedModel_Inverter,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_Mod,
};

DataObject iedModel_Inverter_MMXU1_Mod = {
    DataObjectModelType,
    "Mod",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_Beh,
    (ModelNode*) &iedModel_Inverter_MMXU1_Mod_q,
    0
};

DataAttribute iedModel_Inverter_MMXU1_Mod_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_Mod,
    (ModelNode*) &iedModel_Inverter_MMXU1_Mod_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Mod_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_Mod,
    (ModelNode*) &iedModel_Inverter_MMXU1_Mod_ctlModel,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Mod_ctlModel = {
    DataAttributeModelType,
    "ctlModel",
    (ModelNode*) &iedModel_Inverter_MMXU1_Mod,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_Beh = {
    DataObjectModelType,
    "Beh",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_Health,
    (ModelNode*) &iedModel_Inverter_MMXU1_Beh_stVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_Beh_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_Beh,
    (ModelNode*) &iedModel_Inverter_MMXU1_Beh_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Beh_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_Beh,
    (ModelNode*) &iedModel_Inverter_MMXU1_Beh_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Beh_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_Beh,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_Health = {
    DataObjectModelType,
    "Health",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_NamPlt,
    (ModelNode*) &iedModel_Inverter_MMXU1_Health_stVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_Health_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_Health,
    (ModelNode*) &iedModel_Inverter_MMXU1_Health_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Health_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_Health,
    (ModelNode*) &iedModel_Inverter_MMXU1_Health_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Health_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_Health,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_NamPlt = {
    DataObjectModelType,
    "NamPlt",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW,
    (ModelNode*) &iedModel_Inverter_MMXU1_NamPlt_vendor,
    0
};

DataAttribute iedModel_Inverter_MMXU1_NamPlt_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Inverter_MMXU1_NamPlt,
    (ModelNode*) &iedModel_Inverter_MMXU1_NamPlt_swRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_NamPlt_swRev = {
    DataAttributeModelType,
    "swRev",
    (ModelNode*) &iedModel_Inverter_MMXU1_NamPlt,
    (ModelNode*) &iedModel_Inverter_MMXU1_NamPlt_d,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_NamPlt_d = {
    DataAttributeModelType,
    "d",
    (ModelNode*) &iedModel_Inverter_MMXU1_NamPlt,
    NULL,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_TotW = {
    DataObjectModelType,
    "TotW",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW_mag,
    0
};

DataAttribute iedModel_Inverter_MMXU1_TotW_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotW_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotW_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotW_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotW,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_TotVAr = {
    DataObjectModelType,
    "TotVAr",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr_mag,
    0
};

DataAttribute iedModel_Inverter_MMXU1_TotVAr_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotVAr_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotVAr_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotVAr_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVAr,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_TotVA = {
    DataObjectModelType,
    "TotVA",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA_mag,
    0
};

DataAttribute iedModel_Inverter_MMXU1_TotVA_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotVA_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotVA_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA,
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_TotVA_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_TotVA,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_Hz = {
    DataObjectModelType,
    "Hz",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV,
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz_mag,
    0
};

DataAttribute iedModel_Inverter_MMXU1_Hz_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz,
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Hz_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Hz_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz,
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_Hz_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_Hz,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_PhV = {
    DataObjectModelType,
    "PhV",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_A,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA,
    0
};

DataObject iedModel_Inverter_MMXU1_PhV_phsA = {
    DataObjectModelType,
    "phsA",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsA_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsA,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_PhV_phsB = {
    DataObjectModelType,
    "phsB",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsB_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsB,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_PhV_phsC = {
    DataObjectModelType,
    "phsC",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_phsC_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_phsC,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_PhV_neut = {
    DataObjectModelType,
    "neut",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_PhV_neut_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_neut_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_neut_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_neut_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut,
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_PhV_neut_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_PhV_neut,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_A = {
    DataObjectModelType,
    "A",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    (ModelNode*) &iedModel_Inverter_MMXU1_W,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA,
    0
};

DataObject iedModel_Inverter_MMXU1_A_phsA = {
    DataObjectModelType,
    "phsA",
    (ModelNode*) &iedModel_Inverter_MMXU1_A,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_A_phsA_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsA_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsA_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsA_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsA_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsA,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_A_phsB = {
    DataObjectModelType,
    "phsB",
    (ModelNode*) &iedModel_Inverter_MMXU1_A,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_A_phsB_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsB_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsB_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsB_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsB_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsB,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_A_phsC = {
    DataObjectModelType,
    "phsC",
    (ModelNode*) &iedModel_Inverter_MMXU1_A,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_A_phsC_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsC_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsC_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsC_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_phsC_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_phsC,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_A_neut = {
    DataObjectModelType,
    "neut",
    (ModelNode*) &iedModel_Inverter_MMXU1_A,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_A_neut_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_neut_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_neut_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_neut_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut,
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_A_neut_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_A_neut,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_W = {
    DataObjectModelType,
    "W",
    (ModelNode*) &iedModel_Inverter_MMXU1,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA,
    0
};

DataObject iedModel_Inverter_MMXU1_W_phsA = {
    DataObjectModelType,
    "phsA",
    (ModelNode*) &iedModel_Inverter_MMXU1_W,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_W_phsA_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsA_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsA_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsA_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsA_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsA,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_W_phsB = {
    DataObjectModelType,
    "phsB",
    (ModelNode*) &iedModel_Inverter_MMXU1_W,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_W_phsB_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsB_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsB_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsB_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsB_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsB,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Inverter_MMXU1_W_phsC = {
    DataObjectModelType,
    "phsC",
    (ModelNode*) &iedModel_Inverter_MMXU1_W,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC_cVal,
    0
};

DataAttribute iedModel_Inverter_MMXU1_W_phsC_cVal = {
    DataAttributeModelType,
    "cVal",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC_q,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC_cVal_mag,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsC_cVal_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC_cVal,
    NULL,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC_cVal_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsC_cVal_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC_cVal_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsC_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC,
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Inverter_MMXU1_W_phsC_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Inverter_MMXU1_W_phsC,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};


LogicalDevice iedModel_Battery = {
    LogicalDeviceModelType,
    "ied1Battery",
    (ModelNode*) &iedModel,
    (ModelNode*) &iedModel_Physical_Measurements,
    (ModelNode*) &iedModel_Battery_LLN0
};

LogicalNode iedModel_Battery_LLN0 = {
    LogicalNodeModelType,
    "LLN0",
    (ModelNode*) &iedModel_Battery,
    (ModelNode*) &iedModel_Battery_LPHD1,
    (ModelNode*) &iedModel_Battery_LLN0_Mod,
};

DataObject iedModel_Battery_LLN0_Mod = {
    DataObjectModelType,
    "Mod",
    (ModelNode*) &iedModel_Battery_LLN0,
    (ModelNode*) &iedModel_Battery_LLN0_Beh,
    (ModelNode*) &iedModel_Battery_LLN0_Mod_q,
    0
};

DataAttribute iedModel_Battery_LLN0_Mod_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_LLN0_Mod,
    (ModelNode*) &iedModel_Battery_LLN0_Mod_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_Mod_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_LLN0_Mod,
    (ModelNode*) &iedModel_Battery_LLN0_Mod_ctlModel,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_Mod_ctlModel = {
    DataAttributeModelType,
    "ctlModel",
    (ModelNode*) &iedModel_Battery_LLN0_Mod,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Battery_LLN0_Beh = {
    DataObjectModelType,
    "Beh",
    (ModelNode*) &iedModel_Battery_LLN0,
    (ModelNode*) &iedModel_Battery_LLN0_Health,
    (ModelNode*) &iedModel_Battery_LLN0_Beh_stVal,
    0
};

DataAttribute iedModel_Battery_LLN0_Beh_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Battery_LLN0_Beh,
    (ModelNode*) &iedModel_Battery_LLN0_Beh_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_Beh_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_LLN0_Beh,
    (ModelNode*) &iedModel_Battery_LLN0_Beh_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_Beh_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_LLN0_Beh,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_LLN0_Health = {
    DataObjectModelType,
    "Health",
    (ModelNode*) &iedModel_Battery_LLN0,
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt,
    (ModelNode*) &iedModel_Battery_LLN0_Health_stVal,
    0
};

DataAttribute iedModel_Battery_LLN0_Health_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Battery_LLN0_Health,
    (ModelNode*) &iedModel_Battery_LLN0_Health_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_Health_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_LLN0_Health,
    (ModelNode*) &iedModel_Battery_LLN0_Health_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_Health_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_LLN0_Health,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_LLN0_NamPlt = {
    DataObjectModelType,
    "NamPlt",
    (ModelNode*) &iedModel_Battery_LLN0,
    NULL,
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt_vendor,
    0
};

DataAttribute iedModel_Battery_LLN0_NamPlt_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt,
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt_swRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_NamPlt_swRev = {
    DataAttributeModelType,
    "swRev",
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt,
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt_d,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_NamPlt_d = {
    DataAttributeModelType,
    "d",
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt,
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt_configRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_NamPlt_configRev = {
    DataAttributeModelType,
    "configRev",
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt,
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt_ldNs,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_LLN0_NamPlt_ldNs = {
    DataAttributeModelType,
    "ldNs",
    (ModelNode*) &iedModel_Battery_LLN0_NamPlt,
    NULL,
    NULL,
    0,
    EX,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

LogicalNode iedModel_Battery_LPHD1 = {
    LogicalNodeModelType,
    "LPHD1",
    (ModelNode*) &iedModel_Battery,
    (ModelNode*) &iedModel_Battery_ZBAT1,
    (ModelNode*) &iedModel_Battery_LPHD1_PhyNam,
};

DataObject iedModel_Battery_LPHD1_PhyNam = {
    DataObjectModelType,
    "PhyNam",
    (ModelNode*) &iedModel_Battery_LPHD1,
    (ModelNode*) &iedModel_Battery_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Battery_LPHD1_PhyNam_vendor,
    0
};

DataAttribute iedModel_Battery_LPHD1_PhyNam_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Battery_LPHD1_PhyNam,
    NULL,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataObject iedModel_Battery_LPHD1_PhyHealth = {
    DataObjectModelType,
    "PhyHealth",
    (ModelNode*) &iedModel_Battery_LPHD1,
    (ModelNode*) &iedModel_Battery_LPHD1_Proxy,
    (ModelNode*) &iedModel_Battery_LPHD1_PhyHealth_stVal,
    0
};

DataAttribute iedModel_Battery_LPHD1_PhyHealth_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Battery_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Battery_LPHD1_PhyHealth_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LPHD1_PhyHealth_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Battery_LPHD1_PhyHealth_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LPHD1_PhyHealth_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_LPHD1_PhyHealth,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_LPHD1_Proxy = {
    DataObjectModelType,
    "Proxy",
    (ModelNode*) &iedModel_Battery_LPHD1,
    NULL,
    (ModelNode*) &iedModel_Battery_LPHD1_Proxy_stVal,
    0
};

DataAttribute iedModel_Battery_LPHD1_Proxy_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Battery_LPHD1_Proxy,
    (ModelNode*) &iedModel_Battery_LPHD1_Proxy_q,
    NULL,
    0,
    ST,
    BOOLEAN,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LPHD1_Proxy_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_LPHD1_Proxy,
    (ModelNode*) &iedModel_Battery_LPHD1_Proxy_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_LPHD1_Proxy_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_LPHD1_Proxy,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

LogicalNode iedModel_Battery_ZBAT1 = {
    LogicalNodeModelType,
    "ZBAT1",
    (ModelNode*) &iedModel_Battery,
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBAT1_Mod,
};

DataObject iedModel_Battery_ZBAT1_Mod = {
    DataObjectModelType,
    "Mod",
    (ModelNode*) &iedModel_Battery_ZBAT1,
    (ModelNode*) &iedModel_Battery_ZBAT1_Beh,
    (ModelNode*) &iedModel_Battery_ZBAT1_Mod_q,
    0
};

DataAttribute iedModel_Battery_ZBAT1_Mod_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBAT1_Mod,
    (ModelNode*) &iedModel_Battery_ZBAT1_Mod_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Mod_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBAT1_Mod,
    (ModelNode*) &iedModel_Battery_ZBAT1_Mod_ctlModel,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Mod_ctlModel = {
    DataAttributeModelType,
    "ctlModel",
    (ModelNode*) &iedModel_Battery_ZBAT1_Mod,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBAT1_Beh = {
    DataObjectModelType,
    "Beh",
    (ModelNode*) &iedModel_Battery_ZBAT1,
    (ModelNode*) &iedModel_Battery_ZBAT1_Health,
    (ModelNode*) &iedModel_Battery_ZBAT1_Beh_stVal,
    0
};

DataAttribute iedModel_Battery_ZBAT1_Beh_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Battery_ZBAT1_Beh,
    (ModelNode*) &iedModel_Battery_ZBAT1_Beh_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Beh_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBAT1_Beh,
    (ModelNode*) &iedModel_Battery_ZBAT1_Beh_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Beh_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBAT1_Beh,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBAT1_Health = {
    DataObjectModelType,
    "Health",
    (ModelNode*) &iedModel_Battery_ZBAT1,
    (ModelNode*) &iedModel_Battery_ZBAT1_NamPlt,
    (ModelNode*) &iedModel_Battery_ZBAT1_Health_stVal,
    0
};

DataAttribute iedModel_Battery_ZBAT1_Health_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Battery_ZBAT1_Health,
    (ModelNode*) &iedModel_Battery_ZBAT1_Health_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Health_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBAT1_Health,
    (ModelNode*) &iedModel_Battery_ZBAT1_Health_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Health_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBAT1_Health,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBAT1_NamPlt = {
    DataObjectModelType,
    "NamPlt",
    (ModelNode*) &iedModel_Battery_ZBAT1,
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol,
    (ModelNode*) &iedModel_Battery_ZBAT1_NamPlt_vendor,
    0
};

DataAttribute iedModel_Battery_ZBAT1_NamPlt_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Battery_ZBAT1_NamPlt,
    (ModelNode*) &iedModel_Battery_ZBAT1_NamPlt_swRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_NamPlt_swRev = {
    DataAttributeModelType,
    "swRev",
    (ModelNode*) &iedModel_Battery_ZBAT1_NamPlt,
    (ModelNode*) &iedModel_Battery_ZBAT1_NamPlt_d,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_NamPlt_d = {
    DataAttributeModelType,
    "d",
    (ModelNode*) &iedModel_Battery_ZBAT1_NamPlt,
    NULL,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBAT1_Vol = {
    DataObjectModelType,
    "Vol",
    (ModelNode*) &iedModel_Battery_ZBAT1,
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp,
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol_mag,
    0
};

DataAttribute iedModel_Battery_ZBAT1_Vol_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol,
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol_q,
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Vol_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Vol_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol,
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Vol_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBAT1_Vol,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBAT1_Amp = {
    DataObjectModelType,
    "Amp",
    (ModelNode*) &iedModel_Battery_ZBAT1,
    NULL,
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp_mag,
    0
};

DataAttribute iedModel_Battery_ZBAT1_Amp_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp,
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp_q,
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Amp_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Amp_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp,
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBAT1_Amp_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBAT1_Amp,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

LogicalNode iedModel_Battery_ZBTC1 = {
    LogicalNodeModelType,
    "ZBTC1",
    (ModelNode*) &iedModel_Battery,
    NULL,
    (ModelNode*) &iedModel_Battery_ZBTC1_Mod,
};

DataObject iedModel_Battery_ZBTC1_Mod = {
    DataObjectModelType,
    "Mod",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBTC1_Beh,
    (ModelNode*) &iedModel_Battery_ZBTC1_Mod_q,
    0
};

DataAttribute iedModel_Battery_ZBTC1_Mod_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBTC1_Mod,
    (ModelNode*) &iedModel_Battery_ZBTC1_Mod_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_Mod_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBTC1_Mod,
    (ModelNode*) &iedModel_Battery_ZBTC1_Mod_ctlModel,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_Mod_ctlModel = {
    DataAttributeModelType,
    "ctlModel",
    (ModelNode*) &iedModel_Battery_ZBTC1_Mod,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBTC1_Beh = {
    DataObjectModelType,
    "Beh",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBTC1_Health,
    (ModelNode*) &iedModel_Battery_ZBTC1_Beh_stVal,
    0
};

DataAttribute iedModel_Battery_ZBTC1_Beh_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Battery_ZBTC1_Beh,
    (ModelNode*) &iedModel_Battery_ZBTC1_Beh_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_Beh_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBTC1_Beh,
    (ModelNode*) &iedModel_Battery_ZBTC1_Beh_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_Beh_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBTC1_Beh,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBTC1_Health = {
    DataObjectModelType,
    "Health",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBTC1_NamPlt,
    (ModelNode*) &iedModel_Battery_ZBTC1_Health_stVal,
    0
};

DataAttribute iedModel_Battery_ZBTC1_Health_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Battery_ZBTC1_Health,
    (ModelNode*) &iedModel_Battery_ZBTC1_Health_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_Health_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBTC1_Health,
    (ModelNode*) &iedModel_Battery_ZBTC1_Health_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_Health_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBTC1_Health,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBTC1_NamPlt = {
    DataObjectModelType,
    "NamPlt",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBTC1_BatChaSt,
    (ModelNode*) &iedModel_Battery_ZBTC1_NamPlt_vendor,
    0
};

DataAttribute iedModel_Battery_ZBTC1_NamPlt_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Battery_ZBTC1_NamPlt,
    (ModelNode*) &iedModel_Battery_ZBTC1_NamPlt_swRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_NamPlt_swRev = {
    DataAttributeModelType,
    "swRev",
    (ModelNode*) &iedModel_Battery_ZBTC1_NamPlt,
    (ModelNode*) &iedModel_Battery_ZBTC1_NamPlt_d,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_NamPlt_d = {
    DataAttributeModelType,
    "d",
    (ModelNode*) &iedModel_Battery_ZBTC1_NamPlt,
    NULL,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBTC1_BatChaSt = {
    DataObjectModelType,
    "BatChaSt",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBTC1_BatChaPwr,
    NULL,
    0
};

DataObject iedModel_Battery_ZBTC1_BatChaPwr = {
    DataObjectModelType,
    "BatChaPwr",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBTC1_BatChaMod,
    NULL,
    0
};

DataObject iedModel_Battery_ZBTC1_BatChaMod = {
    DataObjectModelType,
    "BatChaMod",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV,
    NULL,
    0
};

DataObject iedModel_Battery_ZBTC1_ChaV = {
    DataObjectModelType,
    "ChaV",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV_mag,
    0
};

DataAttribute iedModel_Battery_ZBTC1_ChaV_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV_q,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_ChaV_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_ChaV_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_ChaV_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaV,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Battery_ZBTC1_ChaA = {
    DataObjectModelType,
    "ChaA",
    (ModelNode*) &iedModel_Battery_ZBTC1,
    NULL,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA_mag,
    0
};

DataAttribute iedModel_Battery_ZBTC1_ChaA_mag = {
    DataAttributeModelType,
    "mag",
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA_q,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA_mag_f,
    0,
    MX,
    CONSTRUCTED,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_ChaA_mag_f = {
    DataAttributeModelType,
    "f",
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA_mag,
    NULL,
    NULL,
    0,
    MX,
    FLOAT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_ChaA_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA,
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA_t,
    NULL,
    0,
    MX,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Battery_ZBTC1_ChaA_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Battery_ZBTC1_ChaA,
    NULL,
    NULL,
    0,
    MX,
    TIMESTAMP,
    0,
    NULL,
    0};


LogicalDevice iedModel_Physical_Measurements = {
    LogicalDeviceModelType,
    "ied1Physical_Measurements",
    (ModelNode*) &iedModel,
    NULL,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0
};

LogicalNode iedModel_Physical_Measurements_LLN0 = {
    LogicalNodeModelType,
    "LLN0",
    (ModelNode*) &iedModel_Physical_Measurements,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Mod,
};

DataObject iedModel_Physical_Measurements_LLN0_Mod = {
    DataObjectModelType,
    "Mod",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Beh,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Mod_q,
    0
};

DataAttribute iedModel_Physical_Measurements_LLN0_Mod_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Mod,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Mod_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_Mod_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Mod,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Mod_ctlModel,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_Mod_ctlModel = {
    DataAttributeModelType,
    "ctlModel",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Mod,
    NULL,
    NULL,
    0,
    CF,
    ENUMERATED,
    0,
    NULL,
    0};

DataObject iedModel_Physical_Measurements_LLN0_Beh = {
    DataObjectModelType,
    "Beh",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Health,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Beh_stVal,
    0
};

DataAttribute iedModel_Physical_Measurements_LLN0_Beh_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Beh,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Beh_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_Beh_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Beh,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Beh_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_Beh_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Beh,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Physical_Measurements_LLN0_Health = {
    DataObjectModelType,
    "Health",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Health_stVal,
    0
};

DataAttribute iedModel_Physical_Measurements_LLN0_Health_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Health,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Health_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_Health_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Health,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Health_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_Health_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_Health,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Physical_Measurements_LLN0_NamPlt = {
    DataObjectModelType,
    "NamPlt",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0,
    NULL,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt_vendor,
    0
};

DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt_swRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_swRev = {
    DataAttributeModelType,
    "swRev",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt_d,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_d = {
    DataAttributeModelType,
    "d",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt_configRev,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_configRev = {
    DataAttributeModelType,
    "configRev",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt,
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt_ldNs,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LLN0_NamPlt_ldNs = {
    DataAttributeModelType,
    "ldNs",
    (ModelNode*) &iedModel_Physical_Measurements_LLN0_NamPlt,
    NULL,
    NULL,
    0,
    EX,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

LogicalNode iedModel_Physical_Measurements_LPHD1 = {
    LogicalNodeModelType,
    "LPHD1",
    (ModelNode*) &iedModel_Physical_Measurements,
    NULL,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyNam,
};

DataObject iedModel_Physical_Measurements_LPHD1_PhyNam = {
    DataObjectModelType,
    "PhyNam",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyNam_vendor,
    0
};

DataAttribute iedModel_Physical_Measurements_LPHD1_PhyNam_vendor = {
    DataAttributeModelType,
    "vendor",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyNam,
    NULL,
    NULL,
    0,
    DC,
    VISIBLE_STRING_255,
    0,
    NULL,
    0};

DataObject iedModel_Physical_Measurements_LPHD1_PhyHealth = {
    DataObjectModelType,
    "PhyHealth",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_Proxy,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyHealth_stVal,
    0
};

DataAttribute iedModel_Physical_Measurements_LPHD1_PhyHealth_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyHealth_q,
    NULL,
    0,
    ST,
    INT32,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LPHD1_PhyHealth_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyHealth,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyHealth_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LPHD1_PhyHealth_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_PhyHealth,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};

DataObject iedModel_Physical_Measurements_LPHD1_Proxy = {
    DataObjectModelType,
    "Proxy",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1,
    NULL,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_Proxy_stVal,
    0
};

DataAttribute iedModel_Physical_Measurements_LPHD1_Proxy_stVal = {
    DataAttributeModelType,
    "stVal",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_Proxy,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_Proxy_q,
    NULL,
    0,
    ST,
    BOOLEAN,
    0 + TRG_OPT_DATA_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LPHD1_Proxy_q = {
    DataAttributeModelType,
    "q",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_Proxy,
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_Proxy_t,
    NULL,
    0,
    ST,
    QUALITY,
    0 + TRG_OPT_QUALITY_CHANGED,
    NULL,
    0};

DataAttribute iedModel_Physical_Measurements_LPHD1_Proxy_t = {
    DataAttributeModelType,
    "t",
    (ModelNode*) &iedModel_Physical_Measurements_LPHD1_Proxy,
    NULL,
    NULL,
    0,
    ST,
    TIMESTAMP,
    0,
    NULL,
    0};


extern ReportControlBlock iedModel_Inverter_LLN0_report0;

ReportControlBlock iedModel_Inverter_LLN0_report0 = {&iedModel_Inverter_LLN0, "rcb1", "ID", false, "dataset1", 0, 3, 32, 0, 0, NULL};









































IedModel iedModel = {
    "ied1",
    &iedModel_Inverter,
    &ds_Inverter_LLN0_dataset1,
    &iedModel_Inverter_LLN0_report0,
    NULL,
    initializeValues
};

static void
initializeValues()
{

iedModel_Inverter_LLN0_Mod_ctlModel.mmsValue = MmsValue_newIntegerFromInt32(0);

iedModel_Inverter_ZINV1_Mod_ctlModel.mmsValue = MmsValue_newIntegerFromInt32(0);

iedModel_Inverter_MMXU1_Mod_ctlModel.mmsValue = MmsValue_newIntegerFromInt32(0);

iedModel_Battery_LLN0_Mod_ctlModel.mmsValue = MmsValue_newIntegerFromInt32(0);

iedModel_Battery_ZBAT1_Mod_ctlModel.mmsValue = MmsValue_newIntegerFromInt32(0);

iedModel_Battery_ZBTC1_Mod_ctlModel.mmsValue = MmsValue_newIntegerFromInt32(0);

iedModel_Physical_Measurements_LLN0_Mod_ctlModel.mmsValue = MmsValue_newIntegerFromInt32(0);
}
