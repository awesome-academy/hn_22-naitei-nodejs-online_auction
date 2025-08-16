import * as XLSX from 'xlsx';

/**
 * Đọc file Excel và chuyển đổi thành mảng objects
 * @param {File} file - File Excel
 * @returns {Promise<Array>} - Mảng các object products
 */
export const readExcelFile = (file) => {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();

        reader.onload = (e) => {
            try {
                const data = new Uint8Array(e.target.result);
                const workbook = XLSX.read(data, { type: 'array' });

                // Lấy sheet đầu tiên
                const sheetName = workbook.SheetNames[0];
                const worksheet = workbook.Sheets[sheetName];

                // Chuyển đổi thành JSON
                const jsonData = XLSX.utils.sheet_to_json(worksheet, { header: 1 });

                if (jsonData.length < 2) {
                    reject(new Error('File Excel phải có ít nhất 2 dòng (header và data)'));
                    return;
                }

                // Dòng đầu tiên là header
                const headers = jsonData[0];
                const rows = jsonData.slice(1);

                // Validate headers
                const requiredHeaders = ['Product Name', 'Stock Quantity'];
                const missingHeaders = requiredHeaders.filter(header =>
                    !headers.some(h => h && h.toString().toLowerCase().includes(header.toLowerCase()))
                );

                if (missingHeaders.length > 0) {
                    reject(new Error(`Thiếu các cột bắt buộc: ${missingHeaders.join(', ')}`));
                    return;
                }

                // Tìm index của các cột
                const productNameIndex = headers.findIndex(h =>
                    h && h.toString().toLowerCase().includes('product name')
                );
                const stockQuantityIndex = headers.findIndex(h =>
                    h && h.toString().toLowerCase().includes('stock quantity')
                );
                const descriptionIndex = headers.findIndex(h =>
                    h && h.toString().toLowerCase().includes('description')
                );

                // Chuyển đổi dữ liệu
                const products = rows
                    .filter(row => row[productNameIndex]) // Lọc bỏ dòng trống
                    .map((row, index) => {
                        const productName = row[productNameIndex]?.toString().trim() || '';
                        const stockQuantity = row[stockQuantityIndex] || '';
                        const description = row[descriptionIndex]?.toString().trim() || '';

                        // Validate dữ liệu
                        if (!productName) {
                            throw new Error(`Dòng ${index + 2}: Tên sản phẩm không được để trống`);
                        }

                        const quantity = parseInt(stockQuantity);
                        if (isNaN(quantity) || quantity < 0) {
                            throw new Error(`Dòng ${index + 2}: Số lượng phải là số nguyên dương`);
                        }

                        return {
                            productName,
                            description,
                            stockQuantity: quantity.toString(),
                            uploadedImages: [],
                        };
                    });

                if (products.length === 0) {
                    reject(new Error('Không tìm thấy dữ liệu hợp lệ trong file Excel'));
                    return;
                }

                resolve(products);
            } catch (error) {
                reject(new Error(`Lỗi khi đọc file Excel: ${error.message}`));
            }
        };

        reader.onerror = () => {
            reject(new Error('Lỗi khi đọc file'));
        };

        reader.readAsArrayBuffer(file);
    });
};

/**
 * Tạo file Excel mẫu để download
 * @returns {Blob} - File Excel mẫu
 */
export const createSampleExcelFile = () => {
    const sampleData = [
        ['Product Name', 'Description', 'Stock Quantity'],
        ['iPhone 14 Pro Max', 'Điện thoại thông minh cao cấp từ Apple', '50'],
        ['Samsung Galaxy S23', 'Điện thoại Android flagship', '30'],
        ['MacBook Pro M2', 'Laptop chuyên nghiệp cho công việc và sáng tạo', '15'],
        ['AirPods Pro 2', 'Tai nghe không dây chống ồn', '100'],
    ];

    const worksheet = XLSX.utils.aoa_to_sheet(sampleData);
    const workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Products');

    // Tạo buffer
    const excelBuffer = XLSX.write(workbook, { bookType: 'xlsx', type: 'array' });

    return new Blob([excelBuffer], {
        type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    });
};

/**
 * Download file Excel mẫu
 */
export const downloadSampleExcel = () => {
    const blob = createSampleExcelFile();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = 'sample_products.xlsx';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
};
