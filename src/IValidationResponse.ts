export default interface IValidationResponse {
    error: string | null;
    error_description: string | null;
    email_confirmation_required: boolean | null;
    extend_expired_access_enabled: boolean | null;
    authorized_by_sso: boolean | null;
}