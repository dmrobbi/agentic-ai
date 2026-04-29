"""
Finance Agent — Financial operations and reporting.

Handles transaction recording, budget management, spending analysis,
invoice creation, and financial reporting.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any
from enum import Enum
import logging

from agentic_ai.agents.base import BaseAgent, Permission

logger = logging.getLogger(__name__)


class TransactionType(Enum):
    INCOME = "income"
    EXPENSE = "expense"
    TRANSFER = "transfer"


class BudgetStatus(Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    CLOSED = "closed"


@dataclass
class Transaction:
    txn_id: str
    type: TransactionType
    amount: float
    category: str = ""
    description: str = ""
    date: datetime = field(default_factory=datetime.now)


@dataclass
class Budget:
    budget_id: str
    name: str
    total: float = 0.0
    spent: float = 0.0
    categories: Dict[str, float] = field(default_factory=dict)
    status: BudgetStatus = BudgetStatus.DRAFT


@dataclass
class Invoice:
    invoice_id: str
    customer: str
    amount: float
    items: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "draft"
    created_at: datetime = field(default_factory=datetime.now)


class FinanceAgent(BaseAgent):
    """Finance agent for transaction, budget, and invoice management."""

    agent_type = "finance"
    permission = Permission.STANDARD

    def __init__(self, agent_id: str = None, name: str = None,
                 inference_engine=None, state_store=None, message_bus=None,
                 permission: Permission = None):
        super().__init__(agent_id=agent_id, name=name,
                         inference_engine=inference_engine,
                         state_store=state_store, message_bus=message_bus)
        if permission is not None:
            self.permission = permission
        self.transactions: List[Transaction] = []
        self.budgets: List[Budget] = []
        self.invoices: List[Invoice] = []
        self._tools = {
            "record_transaction": self.record_transaction,
            "create_budget": self.create_budget,
            "analyze_spending": self.analyze_spending,
            "create_invoice": self.create_invoice,
            "generate_report": self.generate_report,
        }

    def record_transaction(self, type: str = "expense", amount: float = 0.0,
                           category: str = "", description: str = "") -> Dict[str, Any]:
        try:
            txn_type = TransactionType(type.lower())
        except ValueError:
            return {"error": f"Invalid transaction type: {type}"}
        txn_id = f"TXN-{len(self.transactions)+1:04d}"
        transaction_id = f"TX-{len(self.transactions)+1:06d}"
        txn = Transaction(txn_id=txn_id, type=txn_type, amount=amount,
                          category=category, description=description)
        self.transactions.append(txn)
        return {"status": "recorded", "transaction_id": transaction_id, "txn_id": txn_id, "type": type, "amount": amount, "category": category}

    def create_budget(self, budget_name: str = "", name: str = "", total: float = 0.0,
                      categories: Dict[str, float] = None,
                      permission: Permission = None) -> Dict[str, Any]:
        # Support both budget_name and name
        budget_label = budget_name or name or "Default Budget"
        budget_id = f"BUD-{len(self.budgets)+1:04d}"
        computed_total = total or sum(categories.values()) if categories else total
        budget = Budget(budget_id=budget_id, name=budget_label, total=computed_total,
                        categories=categories or {})
        self.budgets.append(budget)
        return {"status": "created", "budget_id": budget_id, "name": budget_label, "total": computed_total, "categories": categories or {}, "budget": {"budget_id": budget_id, "name": budget_label, "total": computed_total, "categories": categories or {}}}

    def analyze_spending(self, period: str = "month", category: str = "") -> Dict[str, Any]:
        income = sum(t.amount for t in self.transactions if t.type == TransactionType.INCOME)
        expenses = sum(t.amount for t in self.transactions if t.type == TransactionType.EXPENSE)
        by_category = {}
        expense_transactions = [t for t in self.transactions if t.type == TransactionType.EXPENSE]
        for t in expense_transactions:
            by_category[t.category] = by_category.get(t.category, 0) + t.amount
        return {"period": period, "total_income": income, "total_expense": expenses, "total_spent": expenses, "net": income - expenses, "transaction_count": len(expense_transactions), "by_category": by_category}

    def create_invoice(self, customer: str = "", client: str = "", amount: float = 0.0,
                       items: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        customer = customer or client
        item_subtotal = sum(item.get("amount", item.get("quantity", 1) * item.get("price", 0)) for item in (items or []))
        subtotal = amount or item_subtotal
        invoice_id = f"INV-{len(self.invoices)+1:04d}"
        invoice = Invoice(invoice_id=invoice_id, customer=customer, amount=subtotal, items=items or [])
        self.invoices.append(invoice)
        return {"status": "created", "invoice_id": invoice_id, "customer": customer, "amount": subtotal, "invoice": {"invoice_id": invoice_id, "customer": customer, "amount": subtotal, "subtotal": subtotal}}

    def generate_report(self, report_type: str = "summary", period: str = "month") -> Dict[str, Any]:
        income = sum(t.amount for t in self.transactions if t.type == TransactionType.INCOME)
        expenses = sum(t.amount for t in self.transactions if t.type == TransactionType.EXPENSE)
        return {"report_type": report_type, "period": period, "income": income, "expenses": expenses, "net": income - expenses, "budget_count": len(self.budgets), "invoice_count": len(self.invoices)}

    async def perform_task(self, task_type: str = "", **kwargs) -> Dict[str, Any]:
        if task_type == "record_transaction":
            return self.record_transaction(**kwargs)
        elif task_type == "create_budget":
            return self.create_budget(**kwargs)
        elif task_type == "analyze_spending":
            return self.analyze_spending(**kwargs)
        elif task_type == "create_invoice":
            return self.create_invoice(**kwargs)
        elif task_type == "generate_report":
            return self.generate_report(**kwargs)
        return {"error": f"Unknown task type: {task_type}"}