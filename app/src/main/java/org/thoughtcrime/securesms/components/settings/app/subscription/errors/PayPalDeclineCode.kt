package org.thoughtcrime.securesms.components.settings.app.subscription.errors

/**
 * From: https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses#decline-codes
 */
data class PayPalDeclineCode(
  val code: Int
) {

  val knownCode: KnownCode? = KnownCode.fromCode(code)

  enum class KnownCode(val code: Int) {
    DO_NOT_HONOR(2000),
    INSUFFICIENT_FUNDS(2001),
    LIMIT_EXCEEDED(2002),
    CARDHOLDER_ACTIVITY_LIMIT_EXCEEDED(2003),
    EXPIRED_CARD(2004),
    INVALID_CREDIT_CARD(2005),
    INVALID_EXPIRATION_DATE(2006),
    NO_ACCOUNT(2007),
    CARD_ACCOUNT_LENGTH_ERROR(2008),
    NO_SUCH_ISSUER(2009),
    CARD_ISSUER_DECLINED_CVV(2010),
    VOICE_AUTHORIZATION_REQUIRED(2011),
    PROCESSOR_DECLINED_POSSIBLE_LOST_CARD(2012),
    PROCESSOR_DECLINED_POSSIBLE_STOLEN_CARD(2013),
    PROCESSOR_DECLINED_FRAUD_SUSPECTED(2014),
    TRANSACTION_NOT_ALLOWED(2015),
    DUPLICATE_TRANSACTION(2016),
    CARDHOLDER_STOPPED_BILLING(2017),
    CARDHOLDER_STOPPED_ALL_BILLING(2018),
    INVALID_TRANSACTION(2019),
    VIOLATION(2020),
    SECURITY_VIOLATION(2021),
    DECLINED_UPDATED_CARDHOLDER_AVAILABLE(2022),
    PROCESSOR_DOES_NOT_SUPPORT_THIS_FEATURE(2023),
    CARD_TYPE_NOT_ENABLED(2024),
    SET_UP_ERROR_MERCHANT(2025),
    INVALID_MERCHANT_ID(2026),
    SET_UP_ERROR_AMOUNT(2027),
    SET_UP_ERROR_HIERARCHY(2028),
    SET_UP_ERROR_CARD(2029),
    SET_UP_ERROR_TERMINAL(2030),
    ENCRYPTION_ERROR(2031),
    SURCHARGE_NOT_PERMITTED(2032),
    INCONSISTENT_DATA(2033),
    NO_ACTION_TAKEN(2034),
    PARTIAL_APPROVAL_FOR_AMOUNT_IN_GROUP_3_VERSION(2035),
    AUTHORIZATION_COULD_NOT_BE_FOUND(2036),
    ALREADY_REVERSED(2037),
    PROCESSOR_DECLINED(2038),
    INVALID_AUTHORIZATION_CODE(2039),
    INVALID_STORE(2040),
    DECLINED_CALL_FOR_APPROVAL(2041),
    INVALID_CLIENT_ID(2042),
    ERROR_DO_NOT_RETRY_CALL_ISSUER(2043),
    DECLINED_CALL_ISSUER(2044),
    INVALID_MERCHANT_NUMBER(2045),
    DECLINED(2046),
    CALL_ISSUER_PICK_UP_CARD(2047),
    INVALID_AMOUNT(2048),
    INVALID_SKU_NUMBER(2049),
    INVALID_CREDIT_PLAN(2050),
    CREDIT_CARD_NUMBER_DOES_NOT_MATCH_METHOD_OF_PAYMENT(2051),
    INVALID_LEVEL_3_PURCHASE(2052),
    CARD_REPORTED_AS_LOST_OR_STOLEN(2053),
    REVERSAL_AMOUNT_DOES_NOT_MATCH_AUTHORIZATION_AMOUNT(2054),
    INVALID_TRANSACTION_DIVISION_NUMBER(2055),
    TRANSACTION_AMOUNT_EXCEEDS_THE_TRANSACTION_DIVISION_LIMIT(2056),
    ISSUER_OR_CARDHOLDER_HAS_PUT_A_RESTRICTION_ON_THE_CARD(2057),
    MERCHANT_NOT_MASTERCARD_SECURECODE_ENABLED(2058),
    ADDRESS_VERIFICATION_FAILED(2059),
    ADDRESS_VERIFICATION_AND_CARD_SECURITY_CODE_FAILED(2060),
    INVALID_TRANSACTION_DATA(2061),
    INVALID_TAX_AMOUNT(2062),
    PAYPAL_BUSINESS_ACCOUNT_PREFERENCE_RESULTED_IN_THE_TRANSACTION_FAILING(2063),
    INVALID_CURRENCY_CODE(2064),
    REFUND_TIME_LIMIT_EXCEEDED(2065),
    PAYPAL_BUSINESS_ACCOUNT_RESTRICTED(2066),
    AUTHORIZATION_EXPIRED(2067),
    PAYPAL_BUSINESS_ACCOUNT_LOCKED_OR_CLOSED(2068),
    PAYPAL_BLOCKING_DUPLICATE_ORDER_IDS(2069),
    PAYPAL_BUYER_REVOKED_PRE_APPROVED_PAYMENT_AUTHORIZATION(2070),
    PAYPAL_PAYEE_ACCOUNT_INVALID_OR_DOES_NOT_HAVE_A_VERIFIED_EMAIL(2071),
    PAYPAL_PAYEE_EMAIL_INCORRECTLY_FORMATTED(2072),
    PAYPAL_VALIDATION_ERROR(2073),
    FUNDING_INSTRUMENT_IN_THE_PAYPAL_ACCOUNT_WAS_DECLINED_BY_THE_PROCESSR_OR_BANK_OR_IT_CANT_BE_USED_FOR_THIS_PAYMENT(2074),
    PAYER_ACCOUNT_IS_LOCKED_OR_CLOSED(2075),
    PAYER_CANNOT_PAY_FOR_THIS_TRANSACTION_WITH_PAYPAL(2076),
    TRANSACTION_REFUSED_DUE_TO_PAYPAL_RISK_MODEL(2077),
    INVALID_SECURE_PAYMENT_DATA(2078),
    PAYPAL_MERCHANT_ACCOUNT_CONFIGURATION_ERROR(2079),
    INVALID_USER_CREDENTIALS(2080),
    PAYPAL_PENDING_PAYMENTS_ARE_NOT_SUPPORTED(2081),
    PAYPAL_DOMESTIC_TRANSACTION_REQUIRED(2082),
    PAYPAL_PHONE_NUMBER_REQUIRED(2083),
    PAYPAL_TAX_INFO_REQUIRED(2084),
    PAYPAL_PAYEE_BLOCKED_TRANSACTION(2085),
    PAYPAL_TRANSACTION_LIMIT_EXCEEDED(2086),
    PAYPAL_REFERENCE_TRANSACTIONS_ARE_NOT_ENABLED_FOR_YOUR_ACCOUNT(2087),
    CURRENCY_NOT_ENABLED_FOR_YOUR_PAYPAL_SELLER_ACCOUNT(2088),
    PAYPAL_PAYEE_EMAIL_PERMISSION_DENIED_FOR_THIS_REQUEST(2089),
    PAYPAL_OR_VENMO_ACCOUNT_NOT_CONFIGURED_TO_REFUND_MORE_THAN_SETTLED_AMOUNT(2090),
    CURRENCY_OF_THIS_TRANSACTION_MUST_MATCH_CURRENCY_OF_YOUR_PAYPAL_ACCOUNT(2091),
    NO_DATA_FOUND_TRY_ANOTHER_VERIFICATION_METHOD(2092),
    PAYPAL_PAYMENT_METHOD_IS_INVALID(2093),
    PAYPAL_PAYMENT_HAS_ALREADY_BEEN_COMPLETED(2094),
    PAYPAL_REFUND_IS_NOT_ALLOWED_AFTER_PARTIAL_REFUND(2095),
    PAYPAL_BUYER_ACCOUNT_CANT_BE_THE_SAME_AS_THE_SELLER_ACCOUNT(2096),
    PAYPAL_AUTHORIZATION_AMOUNT_LIMIT_EXCEEDED(2097),
    PAYPAL_AUTHORIZATION_COUNT_LIMIT_EXCEEDED(2098),
    CARDHOLDER_AUTHORIZATION_REQUIRED(2099),
    PAYPAL_CHANNEL_INITIATED_BILLING_NOT_ENABLED_FOR_YOUR_ACCOUNT(2100),
    ADDITIONAL_AUTHORIZATION_REQUIRED(2101),
    INCORRECT_PIN(2102),
    PIN_TRY_EXCEEDED(2103),
    OFFLINE_ISSUER_DECLINED(2104),
    CANNOT_AUTHORIZE_AT_THIS_TIME_LIFE_CYCLE(2105),
    CANNOT_AUTHORIZE_AT_THIS_TIME_POLICY(2106),
    CARD_NOT_ACTIVATED(2107),
    CLOSED_CARD(2108),
    PROCESSOR_NETWORK_UNAVAILABLE_TRY_AGAIN(3000);

    companion object {
      fun fromCode(code: Int): KnownCode? = values().firstOrNull { it.code == code }
    }
  }
}
