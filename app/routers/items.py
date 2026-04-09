from http import HTTPStatus

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.database import get_db
from app.models import Item, User
from app.schemas import ItemCreate, ItemRead, ItemUpdate

router = APIRouter(prefix="/items", tags=["items"])


def _get_item_or_404(item_id: int, db: Session) -> Item:
    item = db.query(Item).filter(Item.id == item_id).first()
    if item is None:
        raise HTTPException(status_code=HTTPStatus.NOT_FOUND, detail="Item not found")
    return item


def _assert_item_owner(item: Item, current_user: User) -> None:
    if item.owner_id != current_user.id:
        raise HTTPException(status_code=HTTPStatus.FORBIDDEN, detail="Access denied")


@router.post("", response_model=ItemRead, status_code=HTTPStatus.CREATED)
def create_item(
    payload: ItemCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Item:
    item = Item(
        title=payload.title,
        description=payload.description,
        owner_id=current_user.id,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.get("", response_model=list[ItemRead])
def list_items(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[Item]:
    return db.query(Item).filter(Item.owner_id == current_user.id).all()


@router.get("/{item_id}", response_model=ItemRead)
def get_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Item:
    item = _get_item_or_404(item_id=item_id, db=db)
    _assert_item_owner(item=item, current_user=current_user)
    return item


@router.put("/{item_id}", response_model=ItemRead)
def update_item(
    item_id: int,
    payload: ItemUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Item:
    item = _get_item_or_404(item_id=item_id, db=db)
    _assert_item_owner(item=item, current_user=current_user)

    if payload.title is not None:
        item.title = payload.title
    if payload.description is not None:
        item.description = payload.description

    db.commit()
    db.refresh(item)
    return item


@router.delete("/{item_id}", status_code=HTTPStatus.NO_CONTENT)
def delete_item(
    item_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    item = _get_item_or_404(item_id=item_id, db=db)
    _assert_item_owner(item=item, current_user=current_user)

    db.delete(item)
    db.commit()
