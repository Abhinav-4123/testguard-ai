"""
Stripe Billing Integration
Handles subscriptions, payments, and usage tracking
"""
import os
import logging
from datetime import datetime
from typing import Optional, Dict, List
from fastapi import APIRouter, HTTPException, Request, Header
from pydantic import BaseModel
import stripe

from . import database as db

logger = logging.getLogger("testguard.billing")

# Initialize Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")

router = APIRouter(prefix="/billing", tags=["billing"])

# Pricing Plans
PLANS = {
    "starter": {
        "name": "Starter",
        "price_id": os.getenv("STRIPE_STARTER_PRICE_ID", "price_starter"),
        "price": 499,
        "flows": 3,
        "features": ["Daily smoke tests", "Email alerts", "7-day history"]
    },
    "growth": {
        "name": "Growth",
        "price_id": os.getenv("STRIPE_GROWTH_PRICE_ID", "price_growth"),
        "price": 1499,
        "flows": 10,
        "features": ["Hourly testing", "Slack + Email alerts", "30-day history", "Priority support"]
    },
    "enterprise": {
        "name": "Enterprise",
        "price_id": os.getenv("STRIPE_ENTERPRISE_PRICE_ID", "price_enterprise"),
        "price": 2500,
        "flows": -1,  # Unlimited
        "features": ["Unlimited flows", "Custom integrations", "Compliance reports", "SLA guarantee"]
    }
}


class CreateCustomerRequest(BaseModel):
    email: str
    name: str
    company: Optional[str] = None


class CreateSubscriptionRequest(BaseModel):
    customer_id: str
    plan: str  # starter, growth, enterprise


@router.get("/plans")
async def get_plans():
    """Get available pricing plans"""
    return {"plans": PLANS}


@router.post("/customers")
async def create_customer(request: CreateCustomerRequest):
    """Create a new customer in Stripe"""
    try:
        stripe_customer = stripe.Customer.create(
            email=request.email,
            name=request.name,
            metadata={"company": request.company or ""}
        )

        import uuid
        customer_id = str(uuid.uuid4())
        await db.save_customer(
            customer_id=customer_id,
            email=request.email,
            name=request.name,
            company=request.company,
            stripe_customer_id=stripe_customer.id,
        )

        logger.info("Customer created: %s (%s)", customer_id, request.email)

        return {
            "id": customer_id,
            "email": request.email,
            "name": request.name,
            "company": request.company,
            "stripe_customer_id": stripe_customer.id,
            "status": "created",
        }

    except stripe.error.StripeError as e:
        logger.error("Stripe customer creation failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/subscriptions")
async def create_subscription(request: CreateSubscriptionRequest):
    """Create a subscription for a customer"""
    if request.plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    customer = await db.get_customer(request.customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")

    try:
        subscription = stripe.Subscription.create(
            customer=customer["stripe_customer_id"],
            items=[{"price": PLANS[request.plan]["price_id"]}],
            trial_period_days=7,
            payment_behavior="default_incomplete",
            expand=["latest_invoice.payment_intent"]
        )

        await db.update_customer(
            request.customer_id,
            subscription_id=subscription.id,
            plan=request.plan,
            status=subscription.status,
        )

        logger.info("Subscription created: %s for customer %s", subscription.id, request.customer_id)

        return {
            "subscription_id": subscription.id,
            "status": subscription.status,
            "client_secret": subscription.latest_invoice.payment_intent.client_secret if subscription.latest_invoice.payment_intent else None,
            "trial_end": subscription.trial_end
        }

    except stripe.error.StripeError as e:
        logger.error("Stripe subscription creation failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/checkout-session")
async def create_checkout_session(plan: str, customer_email: str):
    """Create a Stripe Checkout session for easy payment"""
    if plan not in PLANS:
        raise HTTPException(status_code=400, detail="Invalid plan")

    try:
        app_url = os.getenv("APP_URL", "https://app.vibesecurity.in")
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            line_items=[{
                "price": PLANS[plan]["price_id"],
                "quantity": 1
            }],
            mode="subscription",
            success_url=app_url + "/success?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=app_url + "/pricing",
            customer_email=customer_email,
            subscription_data={
                "trial_period_days": 7
            }
        )

        return {"checkout_url": session.url, "session_id": session.id}

    except stripe.error.StripeError as e:
        logger.error("Stripe checkout session failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/webhook")
async def stripe_webhook(request: Request, stripe_signature: str = Header(None)):
    """Handle Stripe webhooks"""
    payload = await request.body()

    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    if event.type == "customer.subscription.created":
        await handle_subscription_created(event.data.object)
    elif event.type == "customer.subscription.updated":
        await handle_subscription_updated(event.data.object)
    elif event.type == "customer.subscription.deleted":
        await handle_subscription_deleted(event.data.object)
    elif event.type == "invoice.paid":
        await handle_invoice_paid(event.data.object)
    elif event.type == "invoice.payment_failed":
        await handle_payment_failed(event.data.object)
    else:
        logger.info("Unhandled Stripe event: %s", event.type)

    return {"status": "success"}


async def handle_subscription_created(subscription):
    """Handle new subscription"""
    logger.info("New subscription: %s (customer: %s)", subscription.id, subscription.customer)


async def handle_subscription_updated(subscription):
    """Handle subscription update (upgrade/downgrade)"""
    logger.info("Subscription updated: %s -> %s", subscription.id, subscription.status)


async def handle_subscription_deleted(subscription):
    """Handle subscription cancellation"""
    logger.info("Subscription canceled: %s", subscription.id)


async def handle_invoice_paid(invoice):
    """Handle successful payment"""
    logger.info("Invoice paid: %s (amount: %s)", invoice.id, invoice.amount_paid)


async def handle_payment_failed(invoice):
    """Handle failed payment"""
    logger.warning("Payment failed: %s (customer: %s)", invoice.id, invoice.customer)


@router.get("/customers/{customer_id}")
async def get_customer(customer_id: str):
    """Get customer details"""
    customer = await db.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    return customer


@router.post("/customers/{customer_id}/cancel")
async def cancel_subscription(customer_id: str):
    """Cancel a customer's subscription"""
    customer = await db.get_customer(customer_id)
    if not customer or not customer.get("subscription_id"):
        raise HTTPException(status_code=404, detail="Subscription not found")

    try:
        stripe.Subscription.delete(customer["subscription_id"])
        await db.update_customer(customer_id, status="canceled")
        logger.info("Subscription canceled for customer: %s", customer_id)
        return {"status": "canceled"}
    except stripe.error.StripeError as e:
        logger.error("Stripe cancellation failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/usage/{customer_id}")
async def get_usage(customer_id: str):
    """Get customer's usage statistics"""
    usage = await db.get_customer_usage(customer_id)
    customer = await db.get_customer(customer_id)
    plan_name = customer.get("plan", "starter") if customer else "starter"
    plan = PLANS.get(plan_name, PLANS["starter"])

    return {
        "customer_id": customer_id,
        "period": "current",
        "tests_run": usage.get("tests_run", 0),
        "tests_limit": plan["flows"] * 30 if plan["flows"] > 0 else -1,
        "alerts_sent": usage.get("alerts_sent", 0),
    }
