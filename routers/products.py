from fastapi import APIRouter, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import httpx
from database import get_db_connection
import os
from pathlib import Path
import uuid
import logging
import asyncio

logger = logging.getLogger(__name__)

# config
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="https://authservices-npr8.onrender.com/auth/token")
router = APIRouter(prefix="/is_products", tags=["Products"])

BLOCKCHAIN_URL = "https://ims-blockchain.onrender.com/blockchain/product"

# helper to get user ID from token
async def get_user_id_from_token(token: str) -> int:
    USER_SERVICE_ME_URL = "https://authservices-npr8.onrender.com/auth/users/me"
    async with httpx.AsyncClient() as client:
        response = await client.get(USER_SERVICE_ME_URL, headers={"Authorization": f"Bearer {token}"})
        response.raise_for_status()
        user_data = response.json()
        return user_data.get("userId")

# image storage config
ROUTER_BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIRECTORY_PHYSICAL = ROUTER_BASE_DIR / "static_files" / "product_images"
UPLOAD_DIRECTORY_PHYSICAL.mkdir(parents=True, exist_ok=True)
logger.info(f"IS: Physical image upload directory set to: {UPLOAD_DIRECTORY_PHYSICAL}")

IMAGE_DB_PATH_PREFIX = "/product_images"
IMAGE_URL_STATIC_PREFIX = "/static_files"
IS_EXTERNAL_BASE_URL = os.getenv("IS_EXTERNAL_URL", "https://ims-productservices.onrender.com")
logger.info(f"IS: External base URL for image links will be: {IS_EXTERNAL_BASE_URL}")

# models
class ProductOut(BaseModel):
    ProductID: int
    ProductName: str
    ProductTypeID: int
    ProductTypeName: str
    ProductCategory: str
    ProductDescription: Optional[str] = None
    ProductPrice: float
    ProductImage: Optional[str] = None
    ProductSizes: Optional[List[str]] = None
    ProductTypeSizeRequired: bool
    Status: Optional[str] = None 
    tx_hash: Optional[str] = None

class ProductSizeCreate(BaseModel):
    SizeName: str

class ProductSizeOut(BaseModel):
    SizeID: int
    ProductID: int
    SizeName: str

class ProductDetailWithStatusOut(BaseModel):
    ProductID: int
    ProductTypeName: str
    ProductCategory: str
    ProductName: str
    Description: Optional[str]
    Price: float
    Sizes: Optional[List[str]]
    Status: str  
    HasAddOns: bool

class ProductAddOnOut(BaseModel):
    AddOnID: int
    AddOnName: str
    Price: float
    Status: str

class ProductLookupRequest(BaseModel):
    productName: str
    category: str

class CartConflictRequest(BaseModel):
    cart_items: List[Dict[str, Any]]
    new_product_id: int

class CartValidationRequest(BaseModel):
    cart_items: List[Dict[str, Any]]

class CartItemRequest(BaseModel):
    cart_items: List[Dict[str, Any]]

# helper functions
async def validate_token_and_roles(token: str, allowed_roles: List[str]):
    USER_SERVICE_ME_URL = "https://authservices-npr8.onrender.com/auth/users/me"
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(USER_SERVICE_ME_URL, headers={"Authorization": f"Bearer {token}"})
            response.raise_for_status()
        except httpx.HTTPStatusError as e:
            error_detail = f"IS Auth service error: {e.response.status_code} - {e.response.text}"
            logger.error(error_detail)
            raise HTTPException(status_code=e.response.status_code, detail=error_detail)
        except httpx.RequestError as e:
            logger.error(f"IS Auth service unavailable: {e}")
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"IS Auth service unavailable: {e}")

    user_data = response.json()
    if user_data.get("userRole") not in allowed_roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")

def _construct_full_url_for_is_response(db_image_path: Optional[str]) -> Optional[str]:
    if db_image_path and db_image_path.startswith(IMAGE_DB_PATH_PREFIX):
        return f"{IS_EXTERNAL_BASE_URL}{IMAGE_URL_STATIC_PREFIX}{db_image_path}"
    return None

async def _get_product_type_details(conn, product_type_id: int) -> Optional[Dict[str, any]]:
    async with conn.cursor() as cursor_type:
        await cursor_type.execute("SELECT ProductTypeName, SizeRequired FROM ProductType WHERE ProductTypeID = ?", product_type_id)
        type_row = await cursor_type.fetchone()
        if type_row:
            return {"name": type_row.ProductTypeName, "size_required": bool(type_row.SizeRequired)}
        return None

# get all products with live stock status
@router.get("/products/details/", response_model=List[ProductDetailWithStatusOut], tags=["Availability of products"])
async def get_all_full_product_details(token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT DISTINCT
                    p.ProductID,
                    p.ProductName,
                    p.ProductDescription,
                    p.ProductPrice,
                    p.ProductCategory,
                    pt.ProductTypeName,
                    CASE
                        WHEN EXISTS (
                            SELECT 1
                            FROM Recipes r_check
                            JOIN RecipeIngredients ri_check ON r_check.RecipeID = ri_check.RecipeID
                            JOIN Ingredients i ON ri_check.IngredientID = i.IngredientID
                            WHERE r_check.ProductID = p.ProductID
                              AND (
                                  LOWER(RTRIM(LTRIM(i.Status))) IN ('not available', 'low stock')
                                  OR (i.ExpirationDate IS NOT NULL AND i.ExpirationDate < GETDATE())
                                  
                                  OR ri_check.Amount >
                                     CASE
                                        WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = LOWER(RTRIM(LTRIM(i.Measurement)))
                                        THEN i.Amount
                                        WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = 'g' AND LOWER(RTRIM(LTRIM(i.Measurement))) = 'kg'
                                        THEN i.Amount * 1000
                                        WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = 'ml' AND LOWER(RTRIM(LTRIM(i.Measurement))) = 'l'
                                        THEN i.Amount * 1000
                                        WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = 'kg' AND LOWER(RTRIM(LTRIM(i.Measurement))) = 'g'
                                        THEN i.Amount / 1000
                                        WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = 'l' AND LOWER(RTRIM(LTRIM(i.Measurement))) = 'ml'
                                        THEN i.Amount / 1000
                                        ELSE i.Amount
                                     END
                              )
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM Recipes r_mat
                            JOIN RecipeMaterials rm ON r_mat.RecipeID = rm.RecipeID
                            JOIN Materials m ON rm.MaterialID = m.MaterialID
                            WHERE r_mat.ProductID = p.ProductID
                              AND (
                                  LOWER(RTRIM(LTRIM(m.Status))) IN ('not available', 'low stock')
                                  OR rm.Quantity > m.MaterialQuantity
                              )
                        ) THEN 'Unavailable'
                        ELSE 'Available'
                    END AS Status,
                    CASE
                        WHEN EXISTS (
                            SELECT 1
                            FROM Recipes r_addons
                            JOIN RecipeAddOns ra ON r_addons.RecipeID = ra.RecipeID
                            WHERE r_addons.ProductID = p.ProductID
                        ) THEN 1
                        ELSE 0
                    END AS HasAddOns
                FROM
                    Products p
                JOIN
                    ProductType pt ON p.ProductTypeID = pt.ProductTypeID
                INNER JOIN
                    Recipes r ON p.ProductID = r.ProductID
                ORDER BY
                    p.ProductName
            """)
            all_products_from_db = await cursor.fetchall()

            product_ids = [p.ProductID for p in all_products_from_db]
            sizes_by_product_id = {}
            if product_ids:
                placeholders = ','.join(['?'] * len(product_ids))
                query = f"SELECT ProductID, SizeName FROM Size WHERE ProductID IN ({placeholders})"
                await cursor.execute(query, *product_ids)
                all_sizes_from_db = await cursor.fetchall()
                for size in all_sizes_from_db:
                    sizes_by_product_id.setdefault(size.ProductID, []).append(size.SizeName)

    except Exception as e:
        logger.error(f"Database error while fetching product details: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while fetching product data.")
    finally:
        if conn:
            await conn.close()

    final_product_list = []
    for product in all_products_from_db:
        final_product_list.append(
            ProductDetailWithStatusOut(
                ProductID=product.ProductID,
                ProductTypeName=product.ProductTypeName,
                ProductCategory=product.ProductCategory,
                ProductName=product.ProductName,
                Description=product.ProductDescription,
                Price=float(product.ProductPrice),
                Sizes=sizes_by_product_id.get(product.ProductID),
                Status=product.Status,
                HasAddOns=bool(product.HasAddOns)
            )
        )
    return final_product_list

# add-ons for a specific product
@router.get("/products/{product_id}/available_addons", response_model=List[ProductAddOnOut])
async def get_available_addons_for_product(product_id: int, token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT
                    ao.AddOnID,
                    ao.AddOnName,
                    ao.Price,
                    i.Status
                FROM Products p
                JOIN Recipes r ON p.ProductID = r.ProductID
                JOIN RecipeAddOns ra ON r.RecipeID = ra.RecipeID
                JOIN AddOns ao ON ra.AddOnID = ao.AddOnID
                JOIN Ingredients i ON ao.IngredientID = i.IngredientID
                WHERE p.ProductID = ? AND i.Status = 'Available'
                ORDER BY ao.AddOnName
            """, product_id)

            addons = await cursor.fetchall()
            return [
                ProductAddOnOut(
                    AddOnID=row.AddOnID,
                    AddOnName=row.AddOnName,
                    Price=float(row.Price),
                    Status=row.Status
                ) for row in addons
            ]
    except Exception as e:
        logger.error(f"Database error fetching add-ons for product {product_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch available add-ons.")
    finally:
        if conn: await conn.close()

# optimized get all add-ons for all products
@router.get("/products/all_addons", response_model=Dict[int, List[ProductAddOnOut]])
async def get_all_available_addons(token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = await get_db_connection()

    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT
                    p.ProductID,
                    ao.AddOnID,
                    ao.AddOnName,
                    ao.Price,
                    i.Status
                FROM Products p
                JOIN Recipes r ON p.ProductID = r.ProductID
                JOIN RecipeAddOns ra ON r.RecipeID = ra.RecipeID
                JOIN AddOns ao ON ra.AddOnID = ao.AddOnID
                JOIN Ingredients i ON ao.IngredientID = i.IngredientID
                WHERE i.Status = 'Available'
                ORDER BY p.ProductID, ao.AddOnName
            """)
            rows = await cursor.fetchall()

        addons_map: Dict[int, List[ProductAddOnOut]] = {}
        for row in rows:
            pid = row.ProductID
            if pid not in addons_map:
                addons_map[pid] = []
            addons_map[pid].append(
                ProductAddOnOut(
                    AddOnID=row.AddOnID,
                    AddOnName=row.AddOnName,
                    Price=float(row.Price),
                    Status=row.Status
                )
            )

        return addons_map

    except Exception as e:
        logger.error(f"Database error fetching all add-ons: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch all available add-ons.")
    finally:
        if conn:
            await conn.close()

# optimized get all add-ons for all products (no auth)
@router.get("/public/products/all_addons", response_model=Dict[int, List[ProductAddOnOut]])
async def get_public_all_addons():
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT
                    p.ProductID,
                    ao.AddOnID,
                    ao.AddOnName,
                    ao.Price,
                    i.Status
                FROM Products p
                JOIN Recipes r ON p.ProductID = r.ProductID
                JOIN RecipeAddOns ra ON r.RecipeID = ra.RecipeID
                JOIN AddOns ao ON ra.AddOnID = ao.AddOnID
                JOIN Ingredients i ON ao.IngredientID = i.IngredientID
                WHERE i.Status = 'Available'
                ORDER BY p.ProductID, ao.AddOnName
            """)
            rows = await cursor.fetchall()

        addons_map = {}
        for row in rows:
            addons_map.setdefault(row.ProductID, []).append(
                ProductAddOnOut(
                    AddOnID=row.AddOnID,
                    AddOnName=row.AddOnName,
                    Price=float(row.Price),
                    Status=row.Status
                )
            )
        return addons_map
    except Exception as e:
        logger.error(f"Database error fetching public all add-ons: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch all available add-ons.")
    finally:
        if conn:
            await conn.close()

# get product details by id
@router.get("/products/{product_id}/details", response_model=ProductDetailWithStatusOut, tags=["product details by ID"])
async def get_full_product_details(product_id: int, token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT
                    p.ProductName,
                    p.ProductDescription,
                    p.ProductPrice,
                    p.ProductCategory,
                    pt.ProductTypeName,
                    CASE
                        WHEN EXISTS (
                            SELECT 1
                            FROM Recipes r
                            JOIN RecipeIngredients ri ON r.RecipeID = ri.RecipeID
                            JOIN Ingredients i ON ri.IngredientID = i.IngredientID
                            WHERE r.ProductID = p.ProductID 
                              AND (i.Status IN ('Not Available', 'Low Stock') OR i.ExpirationDate < GETDATE())
                        )
                        OR EXISTS (
                            SELECT 1
                            FROM Recipes r_mat
                            JOIN RecipeMaterials rm ON r_mat.RecipeID = rm.RecipeID
                            JOIN Materials m ON rm.MaterialID = m.MaterialID
                            WHERE r_mat.ProductID = p.ProductID
                              AND m.Status IN ('Not Available', 'Low Stock')
                        ) THEN 'Unavailable'
                        ELSE 'Available'
                    END AS Status,
                    CASE
                        WHEN EXISTS (
                            SELECT 1
                            FROM Recipes r_addons
                            JOIN RecipeAddOns ra ON r_addons.RecipeID = ra.RecipeID
                            WHERE r_addons.ProductID = p.ProductID
                        ) THEN 1
                        ELSE 0
                    END AS HasAddOns
                FROM
                    Products p
                JOIN
                    ProductType pt ON p.ProductTypeID = pt.ProductTypeID
                WHERE
                    p.ProductID = ?
            """, product_id)
            product_row = await cursor.fetchone()

            if not product_row:
                raise HTTPException(status_code=404, detail=f"Product with ID {product_id} not found.")

            # fetch sizes for this specific product
            await cursor.execute("SELECT SizeName FROM Size WHERE ProductID = ?", product_id)
            product_sizes = [row.SizeName for row in await cursor.fetchall()]

    except Exception as e:
        logger.error(f"Database error while fetching details for product {product_id}: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An error occurred while fetching product data.")
    finally:
        if conn: await conn.close()
    
    return ProductDetailWithStatusOut(
        ProductID=product_id,
        ProductTypeName=product_row.ProductTypeName,
        ProductCategory=product_row.ProductCategory,
        ProductName=product_row.ProductName,
        Description=product_row.ProductDescription,
        Price=float(product_row.ProductPrice),
        Sizes=product_sizes or None,
        Status=product_row.Status,
        HasAddOns=bool(product_row.HasAddOns)
    )

# get all products (no status)
@router.get("/products/", response_model=List[ProductOut])
async def get_all_products(token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT p.ProductID, p.ProductName, p.ProductTypeID, pt.ProductTypeName, pt.SizeRequired,
                       p.ProductCategory, p.ProductDescription, p.ProductPrice, p.ProductImage
                FROM Products p JOIN ProductType pt ON p.ProductTypeID = pt.ProductTypeID
                ORDER BY p.ProductName
            """)
            product_rows = await cursor.fetchall()
            if not product_rows: return []

            product_ids = [r.ProductID for r in product_rows]
            sizes_by_product_id = {}
            if product_ids:
                placeholders = ','.join(['?'] * len(product_ids))
                await cursor.execute(f"SELECT ProductID, SizeName FROM Size WHERE ProductID IN ({placeholders})", *product_ids)
                for sr in await cursor.fetchall():
                    sizes_by_product_id.setdefault(sr.ProductID, []).append(sr.SizeName)
            
            return [ProductOut(
                    ProductID=r.ProductID, ProductName=r.ProductName, ProductTypeID=r.ProductTypeID,
                    ProductTypeName=r.ProductTypeName, ProductCategory=r.ProductCategory,
                    ProductDescription=r.ProductDescription, ProductPrice=float(r.ProductPrice or 0.0),
                    ProductImage=_construct_full_url_for_is_response(r.ProductImage), 
                    ProductSizes=sizes_by_product_id.get(r.ProductID),
                    ProductTypeSizeRequired=bool(r.SizeRequired)
                ) for r in product_rows]
    finally:
        if conn: await conn.close()

# for OOS menu display (no auth)
@router.get("/public/products/", response_model=List[ProductOut])
async def get_public_products():
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("""
    SELECT DISTINCT
        p.ProductID,
        p.ProductName,
        p.ProductTypeID,
        pt.ProductTypeName,
        pt.SizeRequired,
        p.ProductCategory,
        p.ProductDescription,
        p.ProductPrice,
        p.ProductImage,
        CASE
            WHEN EXISTS (
                SELECT 1
                FROM Recipes r_check
                JOIN RecipeIngredients ri_check ON r_check.RecipeID = ri_check.RecipeID
                JOIN Ingredients i ON ri_check.IngredientID = i.IngredientID
                WHERE r_check.ProductID = p.ProductID
                  AND (
                      LOWER(RTRIM(LTRIM(i.Status))) IN ('not available', 'low stock')
                      OR (i.ExpirationDate IS NOT NULL AND i.ExpirationDate < GETDATE())
                      OR ri_check.Amount >
                         CASE
                            WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = LOWER(RTRIM(LTRIM(i.Measurement))) THEN i.Amount
                            WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = 'g'  AND LOWER(RTRIM(LTRIM(i.Measurement))) = 'kg' THEN i.Amount * 1000
                            WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = 'ml' AND LOWER(RTRIM(LTRIM(i.Measurement))) = 'l'  THEN i.Amount * 1000
                            WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = 'kg' AND LOWER(RTRIM(LTRIM(i.Measurement))) = 'g'  THEN i.Amount / 1000
                            WHEN LOWER(RTRIM(LTRIM(ri_check.Measurement))) = 'l'  AND LOWER(RTRIM(LTRIM(i.Measurement))) = 'ml' THEN i.Amount / 1000
                            ELSE i.Amount
                         END
                  )
            )
            OR EXISTS (
                SELECT 1
                FROM Recipes r_mat
                JOIN RecipeMaterials rm ON r_mat.RecipeID = rm.RecipeID
                JOIN Materials m ON rm.MaterialID = m.MaterialID
                WHERE r_mat.ProductID = p.ProductID
                  AND (
                      LOWER(RTRIM(LTRIM(m.Status))) IN ('not available', 'low stock')
                      OR rm.Quantity > m.MaterialQuantity
                  )
            ) THEN 'Unavailable'
            ELSE 'Available'
        END AS Status
    FROM Products p
    JOIN ProductType pt ON p.ProductTypeID = pt.ProductTypeID
    INNER JOIN Recipes r ON p.ProductID = r.ProductID
    INNER JOIN RecipeIngredients ri ON r.RecipeID = ri.RecipeID
    ORDER BY p.ProductName
""")

            product_rows = await cursor.fetchall()
            if not product_rows:
                return []

            # collect all ProductIDs for sizes
            product_ids = [r.ProductID for r in product_rows]
            sizes_by_product_id = {}
            if product_ids:
                placeholders = ','.join(['?'] * len(product_ids))
                await cursor.execute(
                    f"SELECT ProductID, SizeName FROM Size WHERE ProductID IN ({placeholders})",
                    *product_ids
                )
                for sr in await cursor.fetchall():
                    sizes_by_product_id.setdefault(sr.ProductID, []).append(sr.SizeName)

            return [
                ProductOut(
                    ProductID=r.ProductID,
                    ProductName=r.ProductName,
                    ProductTypeID=r.ProductTypeID,
                    ProductTypeName=r.ProductTypeName,
                    ProductCategory=r.ProductCategory,
                    ProductDescription=r.ProductDescription,
                    ProductPrice=float(r.ProductPrice or 0.0),
                    ProductImage=_construct_full_url_for_is_response(r.ProductImage),
                    ProductSizes=sizes_by_product_id.get(r.ProductID),
                    ProductTypeSizeRequired=bool(r.SizeRequired),
                    Status=r.Status  
                )
                for r in product_rows
            ]
    finally:
        if conn:
            await conn.close()

# create product
@router.post("/products/", response_model=ProductOut, status_code=status.HTTP_201_CREATED)
async def create_new_product(
    token: str = Depends(oauth2_scheme), ProductName: str = Form(...), ProductTypeID: int = Form(...),
    ProductCategory: str = Form(...), ProductDescription: Optional[str] = Form(None), ProductPrice: float = Form(...),
    ProductSize: Optional[str] = Form(None), ProductImageFile: Optional[UploadFile] = File(None)
):
    await validate_token_and_roles(token, ["admin", "manager", "staff"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT 1 FROM Products WHERE ProductName = ? AND ProductCategory = ?", ProductName, ProductCategory)
            if await cursor.fetchone():
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"Product '{ProductName}' in '{ProductCategory}' already exists.")

            type_details = await _get_product_type_details(conn, ProductTypeID)
            if not type_details:
                 raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"ProductTypeID {ProductTypeID} not found.")

            is_db_image_path = None
            if ProductImageFile:
                if not ProductImageFile.content_type.startswith("image/"):
                    raise HTTPException(status_code=400, detail="Uploaded file is not a valid image.")
                ext = Path(ProductImageFile.filename).suffix.lower()
                if ext not in [".png", ".jpg", ".jpeg", ".gif", ".webp"]:
                    raise HTTPException(status_code=400, detail=f"Unsupported image extension: {ext}")
                
                unique_filename = f"{uuid.uuid4()}{ext}"
                physical_file_loc = UPLOAD_DIRECTORY_PHYSICAL / unique_filename
                with open(physical_file_loc, "wb") as f:
                    f.write(await ProductImageFile.read())
                is_db_image_path = f"{IMAGE_DB_PATH_PREFIX}/{unique_filename}"
                await ProductImageFile.close()

            await cursor.execute("""
                INSERT INTO Products (ProductName, ProductTypeID, ProductCategory, ProductDescription, ProductPrice, ProductImage)
                OUTPUT INSERTED.ProductID VALUES (?, ?, ?, ?, ?, ?)
            """, ProductName, ProductTypeID, ProductCategory, ProductDescription, ProductPrice, is_db_image_path)
            new_product_id = (await cursor.fetchone()).ProductID

            initial_product_size = None
            if ProductSize and ProductSize.strip():
                initial_product_size = ProductSize.strip()
                await cursor.execute("INSERT INTO Size (ProductID, SizeName) VALUES (?, ?)", new_product_id, initial_product_size)

            await conn.commit()

            # Log to blockchain
            tx_hash_for_response = None
            try:
                user_id = await get_user_id_from_token(token)
                block_payload = {
                    "action": "CREATE",
                    "user_id": user_id,
                    "ProductID": new_product_id,
                    "ProductName": ProductName,
                    "ProductTypeID": ProductTypeID,
                    "ProductCategory": ProductCategory,
                    "ProductDescription": ProductDescription,
                    "ProductPrice": ProductPrice,
                    "ProductImage": is_db_image_path,
                    "ProductSizes": [initial_product_size] if initial_product_size else None,
                    "Status": "Available",
                    "old_values": None,
                    "new_values": {
                        "ProductName": ProductName,
                        "ProductTypeID": ProductTypeID,
                        "ProductCategory": ProductCategory,
                        "ProductDescription": ProductDescription,
                        "ProductPrice": ProductPrice,
                        "ProductImage": is_db_image_path,
                        "ProductSizes": [initial_product_size] if initial_product_size else None,
                        "Status": "Available"
                    }
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        BLOCKCHAIN_URL,
                        json=block_payload,
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    # best-effort: if blockchain service returns JSON with tx_hash include it
                    if resp.status_code in (200, 201):
                        try:
                            resp_json = resp.json()
                            tx_hash_for_response = resp_json.get("tx_hash") or resp_json.get("txHash") or resp_json.get("tx")
                        except Exception:
                            tx_hash_for_response = None
            except Exception as e:
                logger.error(f"Blockchain product log failed: {str(e)}")

            return ProductOut(
                ProductID=new_product_id, ProductName=ProductName, ProductTypeID=ProductTypeID,
                ProductTypeName=type_details["name"], ProductCategory=ProductCategory, ProductDescription=ProductDescription,
                ProductPrice=ProductPrice, ProductImage=_construct_full_url_for_is_response(is_db_image_path),
                ProductSizes=[initial_product_size] if initial_product_size else None,
                ProductTypeSizeRequired=type_details["size_required"],
                tx_hash=tx_hash_for_response
            )
    finally:
        if conn: await conn.close()

# update product
@router.put("/products/{product_id}", response_model=ProductOut)
async def update_product(
    product_id: int, token: str = Depends(oauth2_scheme), ProductName: str = Form(...), ProductTypeID: int = Form(...),
    ProductCategory: str = Form(...), ProductDescription: Optional[str] = Form(None), ProductPrice: float = Form(...),
    ProductSize: Optional[str] = Form(None), ProductImageFile: Optional[UploadFile] = File(None)
):
    await validate_token_and_roles(token, ["admin", "manager", "staff"])
    conn = await get_db_connection()
    try:
        type_details = await _get_product_type_details(conn, ProductTypeID)
        if not type_details:
            raise HTTPException(status_code=400, detail=f"ProductTypeID {ProductTypeID} not found.")

        async with conn.cursor() as cursor:
            # get old values for blockchain logging
            await cursor.execute("SELECT ProductName, ProductTypeID, ProductCategory, ProductDescription, ProductPrice, ProductImage FROM Products WHERE ProductID = ?", product_id)
            old = await cursor.fetchone()
            old_values = {
                "ProductName": old.ProductName if old else None,
                "ProductTypeID": old.ProductTypeID if old else None,
                "ProductCategory": old.ProductCategory if old else None,
                "ProductDescription": old.ProductDescription if old else None,
                "ProductPrice": float(old.ProductPrice) if old and old.ProductPrice is not None else None,
                "ProductImage": old.ProductImage if old else None
            }

            await cursor.execute("SELECT ProductImage FROM Products WHERE ProductID = ?", product_id)
            current_product = await cursor.fetchone()
            if not current_product:
                raise HTTPException(status_code=404, detail="Product not found.")
            
            is_db_image_path_for_update = current_product.ProductImage
            if ProductImageFile:
                unique_filename = f"{uuid.uuid4()}{Path(ProductImageFile.filename).suffix.lower()}"
                physical_file_loc = UPLOAD_DIRECTORY_PHYSICAL / unique_filename
                with open(physical_file_loc, "wb") as f: f.write(await ProductImageFile.read())
                is_db_image_path_for_update = f"{IMAGE_DB_PATH_PREFIX}/{unique_filename}"
                await ProductImageFile.close()
                if current_product.ProductImage:
                    old_file_path = UPLOAD_DIRECTORY_PHYSICAL / Path(current_product.ProductImage).name
                    if old_file_path.exists(): os.remove(old_file_path)

            await cursor.execute("""
                UPDATE Products SET ProductName = ?, ProductTypeID = ?, ProductCategory = ?,
                ProductDescription = ?, ProductPrice = ?, ProductImage = ? WHERE ProductID = ?
            """, ProductName, ProductTypeID, ProductCategory, ProductDescription, ProductPrice, is_db_image_path_for_update, product_id)

            await cursor.execute("DELETE FROM Size WHERE ProductID = ?", product_id)
            product_sizes_for_response = None
            if ProductSize and ProductSize.strip():
                new_size = ProductSize.strip()
                await cursor.execute("INSERT INTO Size (ProductID, SizeName) VALUES (?, ?)", product_id, new_size)
                product_sizes_for_response = [new_size]
            await conn.commit()

            # log to blockchain
            tx_hash_for_response = None
            try:
                user_id = await get_user_id_from_token(token)
                block_payload = {
                    "action": "UPDATE",
                    "user_id": user_id,
                    "ProductID": product_id,
                    "ProductName": ProductName,
                    "ProductTypeID": ProductTypeID,
                    "ProductCategory": ProductCategory,
                    "ProductDescription": ProductDescription,
                    "ProductPrice": float(ProductPrice),
                    "ProductImage": is_db_image_path_for_update,
                    "ProductSizes": product_sizes_for_response,
                    "Status": "Available",
                    "old_values": old_values,
                    "new_values": {
                        "ProductName": ProductName,
                        "ProductTypeID": ProductTypeID,
                        "ProductCategory": ProductCategory,
                        "ProductDescription": ProductDescription,
                        "ProductPrice": float(ProductPrice),
                        "ProductImage": is_db_image_path_for_update,
                        "ProductSizes": product_sizes_for_response,
                        "Status": "Available"
                    }
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        BLOCKCHAIN_URL,
                        json=block_payload,
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    if resp.status_code in (200, 201):
                        try:
                            resp_json = resp.json()
                            tx_hash_for_response = resp_json.get("tx_hash") or resp_json.get("txHash") or resp_json.get("tx")
                        except Exception:
                            tx_hash_for_response = None
            except Exception as e:
                logger.error(f"Blockchain product log failed: {str(e)}")

            return ProductOut(
                ProductID=product_id, ProductName=ProductName, ProductTypeID=ProductTypeID,
                ProductTypeName=type_details['name'], ProductCategory=ProductCategory,
                ProductDescription=ProductDescription, ProductPrice=float(ProductPrice),
                ProductImage=_construct_full_url_for_is_response(is_db_image_path_for_update),
                ProductSizes=product_sizes_for_response,
                ProductTypeSizeRequired=type_details["size_required"],
                tx_hash=tx_hash_for_response
            )
    finally:
        if conn: await conn.close()

# delete product
@router.delete("/products/{product_id}", status_code=status.HTTP_200_OK)
async def delete_product(product_id: int, token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            # get old values for blockchain logging
            await cursor.execute("SELECT ProductName, ProductTypeID, ProductCategory, ProductDescription, ProductPrice, ProductImage FROM Products WHERE ProductID = ?", product_id)
            old = await cursor.fetchone()
            old_values = {
                "ProductName": old.ProductName if old else None,
                "ProductTypeID": old.ProductTypeID if old else None,
                "ProductCategory": old.ProductCategory if old else None,
                "ProductDescription": old.ProductDescription if old else None,
                "ProductPrice": float(old.ProductPrice) if old and old.ProductPrice is not None else None,
                "ProductImage": old.ProductImage if old else None
            }

            await cursor.execute("SELECT ProductImage FROM Products WHERE ProductID = ?", product_id)
            product_row = await cursor.fetchone()
            if not product_row:
                raise HTTPException(status_code=404, detail="Product not found.")
            
            await cursor.execute("DELETE FROM Size WHERE ProductID = ?", product_id)
            await cursor.execute("DELETE FROM Products WHERE ProductID = ?", product_id)
            await conn.commit()

            # log to blockchain
            tx_hash_for_response = None
            try:
                user_id = await get_user_id_from_token(token)
                block_payload = {
                    "action": "DELETE",
                    "user_id": user_id,
                    "ProductID": product_id,
                    "ProductName": old.ProductName if old else None,
                    "ProductTypeID": old.ProductTypeID if old else None,
                    "ProductCategory": old.ProductCategory if old else None,
                    "ProductDescription": old.ProductDescription if old else None,
                    "ProductPrice": float(old.ProductPrice) if old and old.ProductPrice is not None else None,
                    "ProductImage": old.ProductImage if old else None,
                    "ProductSizes": None,
                    "Status": None,
                    "old_values": old_values,
                    "new_values": None
                }
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        BLOCKCHAIN_URL,
                        json=block_payload,
                        headers={"Authorization": f"Bearer {token}"}
                    )
                    if resp.status_code in (200, 201):
                        try:
                            resp_json = resp.json()
                            tx_hash_for_response = resp_json.get("tx_hash") or resp_json.get("txHash") or resp_json.get("tx")
                        except Exception:
                            tx_hash_for_response = None
            except Exception as e:
                logger.error(f"Blockchain product log failed: {str(e)}")

            if product_row.ProductImage:
                physical_file = UPLOAD_DIRECTORY_PHYSICAL / Path(product_row.ProductImage).name
                if physical_file.exists(): os.remove(physical_file)

        msg = f"Product {product_id} and its assets deleted successfully."
        if tx_hash_for_response:
            return {"message": msg, "tx_hash": tx_hash_for_response}
        return {"message": msg}
    finally:
        if conn: await conn.close()

# get product sizes
@router.get("/products/{product_id}/sizes", response_model=List[ProductSizeOut])
async def get_sizes_for_specific_product_is(product_id: int, token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT 1 FROM Products WHERE ProductID = ?", product_id)
            if not await cursor.fetchone():
                raise HTTPException(status_code=404, detail=f"Product ID {product_id} not found.")
            await cursor.execute("SELECT SizeID, ProductID, SizeName FROM Size WHERE ProductID = ? ORDER BY SizeName", product_id)
            return [ProductSizeOut(**dict(zip([c[0] for c in r.cursor_description], r))) for r in await cursor.fetchall()]
    finally:
        if conn: await conn.close()

# add product sizes
@router.post("/products/{product_id}/sizes", response_model=ProductSizeOut, status_code=status.HTTP_201_CREATED)
async def add_size_to_existing_product(product_id: int, size_data: ProductSizeCreate, token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff"])
    conn = await get_db_connection()
    try:
        type_details = await _get_product_type_details(conn, product_id)
        if not type_details or not type_details['size_required']:
            raise HTTPException(status_code=400, detail="This product's type does not require sizes.")
        
        async with conn.cursor() as cursor:
            trimmed_size_name = size_data.SizeName.strip()
            if not trimmed_size_name:
                raise HTTPException(status_code=400, detail="SizeName cannot be empty.")
            
            await cursor.execute("SELECT 1 FROM Size WHERE ProductID = ? AND SizeName = ?", product_id, trimmed_size_name)
            if await cursor.fetchone():
                raise HTTPException(status_code=409, detail=f"Size '{trimmed_size_name}' already exists for this product.")
            
            await cursor.execute("INSERT INTO Size (ProductID, SizeName) OUTPUT INSERTED.SizeID VALUES (?, ?)", product_id, trimmed_size_name)
            new_size_id = (await cursor.fetchone()).SizeID
            await conn.commit()
            return ProductSizeOut(SizeID=new_size_id, ProductID=product_id, SizeName=trimmed_size_name)
    finally:
        if conn: await conn.close()

# delete product size
@router.delete("/products/{product_id}/sizes/{size_id}", status_code=status.HTTP_200_OK)
async def delete_specific_size_from_product_is(product_id: int, size_id: int, token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            delete_op = await cursor.execute("DELETE FROM Size WHERE SizeID = ? AND ProductID = ?", size_id, product_id)
            if delete_op.rowcount == 0:
                raise HTTPException(status_code=404, detail=f"Size ID {size_id} not found for product ID {product_id}.")
            await conn.commit()
        return {"message": f"Size ID {size_id} deleted for product ID {product_id}."}
    finally:
        if conn: await conn.close()

# get total product count
@router.get("/count")
async def get_product_count(token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff"])
    conn = None
    try:
        conn = await get_db_connection()
        async with conn.cursor() as cursor:
            await cursor.execute("SELECT COUNT(*) as count FROM Products")
            row = await cursor.fetchone()
            return {"count": row.count if row else 0}
    finally:
        if conn: await conn.close()

# get inventory by category counts
@router.get("/inventory-by-category")
async def get_inventory_by_category(token: str = Depends(oauth2_scheme)):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier"])
    conn = None
    try:
        conn = await get_db_connection()
        async with conn.cursor() as cursor:
            await cursor.execute("""
                SELECT ProductCategory, COUNT(*) as count
                FROM Products
                GROUP BY ProductCategory
            """)
            rows = await cursor.fetchall()
            return [{"category": row.ProductCategory, "count": row.count} for row in rows]
    finally:
        if conn: await conn.close()

# lookup product by name and category
@router.post("/products/lookup")
async def lookup_product_by_details(
    lookup_data: ProductLookupRequest,
    token: str = Depends(oauth2_scheme)
):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = await get_db_connection()
    try:
        async with conn.cursor() as cursor:
            await cursor.execute(
                """
                SELECT ProductID 
                FROM Products 
                WHERE ProductName = ? AND ProductCategory = ?
                """,
                lookup_data.productName,
                lookup_data.category
            )
            product = await cursor.fetchone()
            
            if not product:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Product '{lookup_data.productName}' in category '{lookup_data.category}' not found"
                )
            
            return {"productId": product.ProductID}
            
    except Exception as e:
        logger.error(f"Error looking up product: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await conn.close()

# check the max quantity available for a product
@router.get("/products/{product_id}/max-quantity")
async def get_max_producible_quantity(
    product_id: int,
    token: str = Depends(oauth2_scheme)
):
    conn = None
    try:
        conn = await get_db_connection()
        async with conn.cursor() as cursor:
            # get product info
            await cursor.execute(
                "SELECT ProductName, ProductCategory FROM Products WHERE ProductID = ?", 
                product_id
            )
            product = await cursor.fetchone()
            if not product:
                raise HTTPException(status_code=404, detail="Product not found")
            
            # get recipe
            await cursor.execute(
                "SELECT RecipeID FROM Recipes WHERE ProductID = ?", 
                product_id
            )
            recipe = await cursor.fetchone()
            if not recipe:
                return {"maxQuantity": 999, "limitedBy": None}
            
            recipe_id = recipe.RecipeID
            max_quantity = float('inf')
            limited_by = None
            
            # check ingredients
            await cursor.execute("""
                SELECT ri.IngredientID, ri.Amount, ri.Measurement,
                       i.Amount AS StockAmount, i.Measurement AS StockUnit,
                       i.IngredientName
                FROM RecipeIngredients ri
                JOIN Ingredients i ON ri.IngredientID = i.IngredientID
                WHERE ri.RecipeID = ?
            """, recipe_id)
            
            ingredients = await cursor.fetchall()
            for ing in ingredients:
                required_per_unit = ing.Amount
                stock_available = float(ing.StockAmount)
                
                # convert units if necessary
                if ing.Measurement.lower() != ing.StockUnit.lower():
                    required_per_unit = convert_units(
                        required_per_unit, 
                        ing.Measurement, 
                        ing.StockUnit
                    )
                
                # calculate possible quantity
                if required_per_unit > 0:
                    possible_qty = int(stock_available / required_per_unit)
                    if possible_qty < max_quantity:
                        max_quantity = possible_qty
                        limited_by = f"Ingredient: {ing.IngredientName}"
            
            # check materials
            await cursor.execute("""
                SELECT rm.MaterialID, rm.Quantity,
                       m.MaterialQuantity, m.MaterialName
                FROM RecipeMaterials rm
                JOIN Materials m ON rm.MaterialID = m.MaterialID
                WHERE rm.RecipeID = ?
            """, recipe_id)
            
            materials = await cursor.fetchall()
            for mat in materials:
                required_per_unit = mat.Quantity
                stock_available = float(mat.MaterialQuantity)
                
                if required_per_unit > 0:
                    possible_qty = int(stock_available / required_per_unit)
                    if possible_qty < max_quantity:
                        max_quantity = possible_qty
                        limited_by = f"Material: {mat.MaterialName}"
            
            # cap max quantity at 999 
            if max_quantity == float('inf'):
                max_quantity = 999
            
            return {
                "maxQuantity": max(0, max_quantity),
                "limitedBy": limited_by,
                "productName": product.ProductName
            }
            
    except Exception as e:
        logger.error(f"Error checking product availability: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await conn.close()

# utility to convert units
def convert_units(amount: float, from_unit: str, to_unit: str) -> float:
    if not from_unit or not to_unit:
        return amount
    
    from_u = from_unit.lower()
    to_u = to_unit.lower()
    
    if from_u == to_u:
        return amount
    
    conversion_factors = {
        ('g', 'kg'): 0.001,
        ('kg', 'g'): 1000,
        ('ml', 'l'): 0.001,
        ('l', 'ml'): 1000,
    }
    
    factor = conversion_factors.get((from_u, to_u))
    if factor is None:
        return amount
    
    return amount * factor

# check cart conflicts
@router.post("/products/check-cart-conflicts")
async def check_cart_conflicts(
    request: CartConflictRequest,
    token: str = Depends(oauth2_scheme)
):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = await get_db_connection()
    
    try:
        async with conn.cursor() as cursor:
            conflicts = []
            
            # get recipe 
            await cursor.execute("""
                SELECT RecipeID FROM Recipes WHERE ProductID = ?
            """, request.new_product_id)
            new_recipe_row = await cursor.fetchone()
            
            if not new_recipe_row:
                return {"canAdd": True, "conflicts": []}
            
            new_recipe_id = new_recipe_row.RecipeID
            
            # get ingredients
            await cursor.execute("""
                SELECT ri.IngredientID, i.IngredientName, ri.Amount, ri.Measurement,
                       i.Amount AS StockAmount, i.Measurement AS StockUnit
                FROM RecipeIngredients ri
                JOIN Ingredients i ON ri.IngredientID = i.IngredientID
                WHERE ri.RecipeID = ?
            """, new_recipe_id)
            new_ingredients = await cursor.fetchall()
            
            # get materials
            await cursor.execute("""
                SELECT rm.MaterialID, m.MaterialName, rm.Quantity,
                       m.MaterialQuantity AS StockQuantity
                FROM RecipeMaterials rm
                JOIN Materials m ON rm.MaterialID = m.MaterialID
                WHERE rm.RecipeID = ?
            """, new_recipe_id)
            new_materials = await cursor.fetchall()
            
            # Get addons for new product
            await cursor.execute("""
                SELECT a.AddOnID, a.AddOnName, a.IngredientID, a.Amount,
                       i.Amount AS StockAmount
                FROM RecipeAddOns ra
                JOIN AddOns a ON ra.AddOnID = a.AddOnID
                JOIN Ingredients i ON a.IngredientID = i.IngredientID
                WHERE ra.RecipeID = ?
            """, new_recipe_id)
            new_addons = await cursor.fetchall()
            
            # check each cart item
            for cart_item in request.cart_items:
                await cursor.execute("""
                    SELECT ProductID FROM Products 
                    WHERE ProductName = ? AND ProductCategory = ?
                """, (cart_item['name'], cart_item.get('category', '')))
                
                cart_product_row = await cursor.fetchone()
                if not cart_product_row:
                    continue
                    
                cart_product_id = cart_product_row.ProductID
                
                # get recipe for cart item
                await cursor.execute("""
                    SELECT RecipeID FROM Recipes WHERE ProductID = ?
                """, cart_product_id)
                cart_recipe_row = await cursor.fetchone()
                
                if not cart_recipe_row:
                    continue
                    
                cart_recipe_id = cart_recipe_row.RecipeID
                # get ingredients for cart item
                await cursor.execute("""
                    SELECT ri.IngredientID, i.IngredientName, ri.Amount, ri.Measurement,
                           i.Amount AS StockAmount, i.Measurement AS StockUnit
                    FROM RecipeIngredients ri
                    JOIN Ingredients i ON ri.IngredientID = i.IngredientID
                    WHERE ri.RecipeID = ?
                """, cart_recipe_id)
                cart_ingredients = await cursor.fetchall()
                
                # check ingredient conflicts
                for new_ing in new_ingredients:
                    for cart_ing in cart_ingredients:
                        if new_ing.IngredientID == cart_ing.IngredientID:
                            # convert units if needed
                            cart_needed = convert_units(
                                cart_ing.Amount * cart_item['quantity'],
                                cart_ing.Measurement,
                                cart_ing.StockUnit
                            )
                            new_needed = convert_units(
                                new_ing.Amount,
                                new_ing.Measurement,
                                new_ing.StockUnit
                            )
                            
                            total_needed = cart_needed + new_needed
                            available = float(new_ing.StockAmount)
                            
                            if total_needed > available:
                                conflicts.append({
                                    "type": "ingredient",
                                    "name": new_ing.IngredientName,
                                    "needed": round(total_needed, 2),
                                    "available": round(available, 2),
                                    "conflictsWith": cart_item['name']
                                })
                
                # get materials for cart item
                await cursor.execute("""
                    SELECT rm.MaterialID, m.MaterialName, rm.Quantity,
                           m.MaterialQuantity AS StockQuantity
                    FROM RecipeMaterials rm
                    JOIN Materials m ON rm.MaterialID = m.MaterialID
                    WHERE rm.RecipeID = ?
                """, cart_recipe_id)
                cart_materials = await cursor.fetchall()
                
                # check material conflicts
                for new_mat in new_materials:
                    for cart_mat in cart_materials:
                        if new_mat.MaterialID == cart_mat.MaterialID:
                            total_needed = (cart_mat.Quantity * cart_item['quantity']) + new_mat.Quantity
                            available = float(new_mat.StockQuantity)
                            
                            if total_needed > available:
                                conflicts.append({
                                    "type": "material",
                                    "name": new_mat.MaterialName,
                                    "needed": round(total_needed, 2),
                                    "available": round(available, 2),
                                    "conflictsWith": cart_item['name']
                                })
                
                # check addon conflicts (if cart item has addons)
                if cart_item.get('addons'):
                    for cart_addon in cart_item['addons']:
                        await cursor.execute("""
                            SELECT IngredientID, Amount FROM AddOns WHERE AddOnID = ?
                        """, cart_addon['addonId'])
                        cart_addon_row = await cursor.fetchone()
                        
                        if cart_addon_row:
                            for new_addon in new_addons:
                                if new_addon.IngredientID == cart_addon_row.IngredientID:
                                    cart_addon_needed = cart_addon_row.Amount * cart_addon['quantity'] * cart_item['quantity']
                                    new_addon_needed = new_addon.Amount
                                    total_needed = cart_addon_needed + new_addon_needed
                                    available = float(new_addon.StockAmount)
                                    
                                    if total_needed > available:
                                        conflicts.append({
                                            "type": "addon",
                                            "name": new_addon.AddOnName,
                                            "needed": round(total_needed, 2),
                                            "available": round(available, 2),
                                            "conflictsWith": f"{cart_item['name']} (addon: {cart_addon['addonName']})"
                                        })         
            return {
                "canAdd": len(conflicts) == 0,
                "conflicts": conflicts
            }
            
    except Exception as e:
        logger.error(f"Error checking cart conflicts: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await conn.close()

@router.post("/products/check-quantity-increase")
async def check_quantity_increase(
    request: CartValidationRequest,
    token: str = Depends(oauth2_scheme)
):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = await get_db_connection()
    
    try:
        async with conn.cursor() as cursor:
            conflicts = []
            ingredient_usage = {}
            material_usage = {}
            
            # check total usage including cart items
            for cart_item in request.cart_items:
                await cursor.execute("""
                    SELECT ProductID FROM Products 
                    WHERE ProductName = ? AND ProductCategory = ?
                """, (cart_item['name'], cart_item.get('category', '')))
                
                cart_product_row = await cursor.fetchone()
                if not cart_product_row:
                    continue
                    
                cart_product_id = cart_product_row.ProductID
                
                # get recipe
                await cursor.execute("""
                    SELECT RecipeID FROM Recipes WHERE ProductID = ?
                """, cart_product_id)
                cart_recipe_row = await cursor.fetchone()
                
                if not cart_recipe_row:
                    continue
                    
                cart_recipe_id = cart_recipe_row.RecipeID
                
                # get ingredients
                await cursor.execute("""
                    SELECT ri.IngredientID, i.IngredientName, ri.Amount, ri.Measurement,
                           i.Amount AS StockAmount, i.Measurement AS StockUnit
                    FROM RecipeIngredients ri
                    JOIN Ingredients i ON ri.IngredientID = i.IngredientID
                    WHERE ri.RecipeID = ?
                """, cart_recipe_id)
                cart_ingredients = await cursor.fetchall()
                
                # check ingredient usage
                for cart_ing in cart_ingredients:
                    cart_needed = convert_units(
                        cart_ing.Amount * cart_item['quantity'],
                        cart_ing.Measurement,
                        cart_ing.StockUnit
                    )
                    
                    if cart_ing.IngredientID not in ingredient_usage:
                        ingredient_usage[cart_ing.IngredientID] = {
                            'total': 0,
                            'name': cart_ing.IngredientName,
                            'stock': float(cart_ing.StockAmount),
                            'items': []
                        }
                    
                    ingredient_usage[cart_ing.IngredientID]['total'] += cart_needed
                    ingredient_usage[cart_ing.IngredientID]['items'].append(
                        f"{cart_item['name']} (x{cart_item['quantity']})"
                    )
                
                # get materials
                await cursor.execute("""
                    SELECT rm.MaterialID, m.MaterialName, rm.Quantity,
                           m.MaterialQuantity AS StockQuantity
                    FROM RecipeMaterials rm
                    JOIN Materials m ON rm.MaterialID = m.MaterialID
                    WHERE rm.RecipeID = ?
                """, cart_recipe_id)
                cart_materials = await cursor.fetchall()
                
                # check material usage
                for cart_mat in cart_materials:
                    mat_needed = cart_mat.Quantity * cart_item['quantity']
                    
                    if cart_mat.MaterialID not in material_usage:
                        material_usage[cart_mat.MaterialID] = {
                            'total': 0,
                            'name': cart_mat.MaterialName,
                            'stock': float(cart_mat.StockQuantity),
                            'items': []
                        }
                    
                    material_usage[cart_mat.MaterialID]['total'] += mat_needed
                    material_usage[cart_mat.MaterialID]['items'].append(
                        f"{cart_item['name']} (x{cart_item['quantity']})"
                    )
                
                # check addons
                if cart_item.get('addons'):
                    for cart_addon in cart_item['addons']:
                        await cursor.execute("""
                            SELECT IngredientID, Amount, AddOnName FROM AddOns WHERE AddOnID = ?
                        """, cart_addon['addonId'])
                        cart_addon_row = await cursor.fetchone()
                        
                        if cart_addon_row:
                            addon_needed = cart_addon_row.Amount * cart_addon['quantity'] * cart_item['quantity']
                            
                            if cart_addon_row.IngredientID not in ingredient_usage:
                                await cursor.execute("""
                                    SELECT IngredientName, Amount FROM Ingredients WHERE IngredientID = ?
                                """, cart_addon_row.IngredientID)
                                ing_info = await cursor.fetchone()
                                
                                ingredient_usage[cart_addon_row.IngredientID] = {
                                    'total': 0,
                                    'name': ing_info.IngredientName if ing_info else 'Unknown',
                                    'stock': float(ing_info.Amount) if ing_info else 0,
                                    'items': []
                                }
                            
                            ingredient_usage[cart_addon_row.IngredientID]['total'] += addon_needed
                            ingredient_usage[cart_addon_row.IngredientID]['items'].append(
                                f"{cart_item['name']} (addon: {cart_addon['addonName']}, x{cart_addon['quantity']})"
                            )
            
            # check if any ingredient exceeds available stock
            for ing_id, usage in ingredient_usage.items():
                if usage['total'] > usage['stock']:
                    conflicts.append({
                        "type": "ingredient",
                        "name": usage['name'],
                        "needed": round(usage['total'], 2),
                        "available": round(usage['stock'], 2),
                        "conflictsWith": ", ".join(usage['items'])
                    })
            
            # check if any material exceeds available stock
            for mat_id, usage in material_usage.items():
                if usage['total'] > usage['stock']:
                    conflicts.append({
                        "type": "material",
                        "name": usage['name'],
                        "needed": round(usage['total'], 2),
                        "available": round(usage['stock'], 2),
                        "conflictsWith": ", ".join(usage['items'])
                    })
            
            return {
                "canAdd": len(conflicts) == 0,
                "conflicts": conflicts
            }
            
    except Exception as e:
        logger.error(f"Error validating cart quantities: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await conn.close()

# check max quantity for current cart items
@router.post("/products/{product_id}/dynamic-max-quantity")
async def get_dynamic_max_quantity(
    product_id: int,
    request: CartItemRequest,
    token: str = Depends(oauth2_scheme)
):
    await validate_token_and_roles(token, ["admin", "manager", "staff", "cashier", "user"])
    conn = None
    try:
        conn = await get_db_connection()
        async with conn.cursor() as cursor:
            # get product info
            await cursor.execute(
                "SELECT ProductName, ProductCategory FROM Products WHERE ProductID = ?", 
                product_id
            )
            product = await cursor.fetchone()
            if not product:
                raise HTTPException(status_code=404, detail="Product not found")
            
            # get recipe
            await cursor.execute(
                "SELECT RecipeID FROM Recipes WHERE ProductID = ?", 
                product_id
            )
            recipe = await cursor.fetchone()
            if not recipe:
                return {"maxQuantity": 999, "limitedBy": None, "productName": product.ProductName}
            
            recipe_id = recipe.RecipeID
            
            ingredient_usage = {}
            material_usage = {}
            
            for cart_item in request.cart_items:
                if cart_item.get('id') == product_id:
                    continue
                
                await cursor.execute("""
                    SELECT ProductID FROM Products 
                    WHERE ProductName = ? AND ProductCategory = ?
                """, (cart_item['name'], cart_item.get('category', '')))
                
                cart_product_row = await cursor.fetchone()
                if not cart_product_row:
                    continue
                    
                cart_product_id = cart_product_row.ProductID
                
                # get recipe for cart item
                await cursor.execute("""
                    SELECT RecipeID FROM Recipes WHERE ProductID = ?
                """, cart_product_id)
                cart_recipe_row = await cursor.fetchone()
                
                if not cart_recipe_row:
                    continue
                    
                cart_recipe_id = cart_recipe_row.RecipeID
                
                # get ingredients for cart item
                await cursor.execute("""
                    SELECT ri.IngredientID, ri.Amount, ri.Measurement,
                           i.Measurement AS StockUnit
                    FROM RecipeIngredients ri
                    JOIN Ingredients i ON ri.IngredientID = i.IngredientID
                    WHERE ri.RecipeID = ?
                """, cart_recipe_id)
                cart_ingredients = await cursor.fetchall()
                
                # check ingredient usage
                for ing in cart_ingredients:
                    usage = convert_units(
                        ing.Amount * cart_item['quantity'],
                        ing.Measurement,
                        ing.StockUnit
                    )
                    ingredient_usage[ing.IngredientID] = ingredient_usage.get(ing.IngredientID, 0) + usage
                
                # get materials for cart item
                await cursor.execute("""
                    SELECT rm.MaterialID, rm.Quantity
                    FROM RecipeMaterials rm
                    WHERE rm.RecipeID = ?
                """, cart_recipe_id)
                cart_materials = await cursor.fetchall()
                
                # check material usage
                for mat in cart_materials:
                    usage = mat.Quantity * cart_item['quantity']
                    material_usage[mat.MaterialID] = material_usage.get(mat.MaterialID, 0) + usage
                
                # handle addons in cart
                if cart_item.get('addons'):
                    for addon in cart_item['addons']:
                        await cursor.execute("""
                            SELECT IngredientID, Amount FROM AddOns WHERE AddOnID = ?
                        """, addon['addonId'])
                        addon_row = await cursor.fetchone()
                        
                        if addon_row:
                            usage = addon_row.Amount * addon['quantity'] * cart_item['quantity']
                            ingredient_usage[addon_row.IngredientID] = \
                                ingredient_usage.get(addon_row.IngredientID, 0) + usage
            
            max_quantity = float('inf')
            limited_by = None
            
            await cursor.execute("""
                SELECT ri.IngredientID, ri.Amount, ri.Measurement,
                       i.Amount AS StockAmount, i.Measurement AS StockUnit,
                       i.IngredientName
                FROM RecipeIngredients ri
                JOIN Ingredients i ON ri.IngredientID = i.IngredientID
                WHERE ri.RecipeID = ?
            """, recipe_id)
            
            ingredients = await cursor.fetchall()
            for ing in ingredients:
                required_per_unit = ing.Amount
                stock_available = float(ing.StockAmount)
                
                # subtract usage from other cart items
                already_used = ingredient_usage.get(ing.IngredientID, 0)
                remaining_stock = stock_available - already_used
                
                # convert units if necessary
                if ing.Measurement.lower() != ing.StockUnit.lower():
                    required_per_unit = convert_units(
                        required_per_unit, 
                        ing.Measurement, 
                        ing.StockUnit
                    )
                
                # check possible quantity with remaining stock
                if required_per_unit > 0:
                    possible_qty = int(remaining_stock / required_per_unit)
                    if possible_qty < max_quantity:
                        max_quantity = possible_qty
                        limited_by = f"Ingredient: {ing.IngredientName}"
            
            # check materials
            await cursor.execute("""
                SELECT rm.MaterialID, rm.Quantity,
                       m.MaterialQuantity, m.MaterialName
                FROM RecipeMaterials rm
                JOIN Materials m ON rm.MaterialID = m.MaterialID
                WHERE rm.RecipeID = ?
            """, recipe_id)
            
            materials = await cursor.fetchall()
            for mat in materials:
                required_per_unit = mat.Quantity
                stock_available = float(mat.MaterialQuantity)
                
                # subtract usage from other cart items
                already_used = material_usage.get(mat.MaterialID, 0)
                remaining_stock = stock_available - already_used
                
                if required_per_unit > 0:
                    possible_qty = int(remaining_stock / required_per_unit)
                    if possible_qty < max_quantity:
                        max_quantity = possible_qty
                        limited_by = f"Material: {mat.MaterialName}"
            
            if max_quantity == float('inf'):
                max_quantity = 999
            
            return {
                "maxQuantity": max(0, max_quantity),
                "limitedBy": limited_by,
                "productName": product.ProductName
            }
            
    except Exception as e:
        logger.error(f"Error calculating dynamic max quantity: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            await conn.close()
            