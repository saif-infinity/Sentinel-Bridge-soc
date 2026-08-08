import logging
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ...db import get_db, get_tenant_id
from ...models import Tenant
from ...auth import has_scopes_or_api_key, get_api_key_or_jwt
from ...config import settings

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/billing", tags=["billing"])

# Plan price IDs (these would be configured in Stripe dashboard)
STRIPE_PLAN_IDS = {
    "basic": "price_basic_monthly",
    "pro": "price_pro_monthly",
    "enterprise": "price_enterprise_monthly",
}


@router.post("/create-checkout-session")
async def create_checkout_session(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(has_scopes_or_api_key(["admin:manage"])),
):
    """Create a Stripe checkout session."""
    tenant_id = get_tenant_id(request)
    body = await request.json()
    plan = body.get("plan")

    if plan not in STRIPE_PLAN_IDS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # For now, return a mock response. Real Stripe integration requires stripe Python package.
    # When stripe is installed, uncomment the real implementation:
    #
    # import stripe
    # stripe.api_key = settings.STRIPE_SECRET_KEY.get_secret_value()
    # session = stripe.checkout.Session.create(
    #     mode="subscription",
    #     customer=tenant.stripe_customer_id,
    #     line_items=[{"price": STRIPE_PLAN_IDS[plan], "quantity": 1}],
    #     success_url=f"{request.base_url}billing/success?session_id={{CHECKOUT_SESSION_ID}}",
    #     cancel_url=f"{request.base_url}pricing",
    #     metadata={"tenant_id": tenant_id, "plan": plan},
    # )
    # return {"checkout_url": session.url, "session_id": session.id}

    return {
        "checkout_url": f"/billing/checkout/mock?plan={plan}&tenant={tenant_id}",
        "session_id": "mock_session",
        "message": "Stripe integration requires stripe package. Configure STRIPE_SECRET_KEY.",
    }


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(get_api_key_or_jwt),  # Require authentication; Stripe signature verification is ideal when stripe package is installed
):
    """Handle Stripe webhook events."""
    body = await request.json()
    event_type = body.get("type", "")

    logger.info("Stripe webhook received: %s", event_type)

    # Real implementation would verify webhook signature:
    # stripe.api_key = settings.STRIPE_SECRET_KEY.get_secret_value()
    # sig_header = request.headers.get("stripe-signature")
    # event = stripe.Webhook.construct_event(await request.body(), sig_header, settings.STRIPE_WEBHOOK_SECRET.get_secret_value())

    data = body.get("data", {}).get("object", {})
    tenant_id = data.get("metadata", {}).get("tenant_id")

    if not tenant_id:
        return {"status": "ignored", "reason": "no tenant_id in metadata"}

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        return {"status": "ignored", "reason": "tenant not found"}

    if event_type == "customer.subscription.created":
        tenant.stripe_subscription_id = data.get("id")
        tenant.status = "active"
        db.commit()
    elif event_type == "customer.subscription.updated":
        # Update plan based on price
        db.commit()
    elif event_type == "customer.subscription.deleted":
        tenant.status = "canceled"
        db.commit()
    elif event_type == "invoice.payment_failed":
        tenant.status = "suspended"
        db.commit()

    return {"status": "processed", "event": event_type}


@router.get("/invoices")
def list_invoices(
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(has_scopes_or_api_key(["admin:manage"])),
):
    """List invoices for current tenant."""
    tenant_id = get_tenant_id(request)
    # Real implementation would query Stripe API
    # For now, return empty list
    return {"invoices": [], "message": "Stripe integration required for invoice history"}
