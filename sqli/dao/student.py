import logging
from typing import Dict, List, Optional, Any

from sqli.dao.base import BaseDao
from sqli.models.student import Student


class StudentDao(BaseDao):
    def __init__(self, db_connection):
        super().__init__(db_connection)
        self.logger = logging.getLogger(self.__class__.__name__)

    def get_all(self) -> List[Student]:
        """
        Get all students from the database
        :return: List of Student objects
        """
        query = "SELECT * FROM students"
        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(query)
        result = cursor.fetchall()
        cursor.close()
        return [Student.from_dict(student) for student in result]

    def get_by_id(self, student_id: int) -> Optional[Student]:
        """
        Get a student by id
        :param student_id: id of the student
        :return: Student object or None if not found
        """
        query = "SELECT * FROM students WHERE id = %s"
        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(query, (student_id,))
        result = cursor.fetchone()
        cursor.close()
        if result:
            return Student.from_dict(result)
        return None

    def get_by_name(self, name: str) -> List[Student]:
        """
        Get students by name
        :param name: name of the student
        :return: List of Student objects
        """
        # Fix: Use parameterized query instead of string formatting
        query = "SELECT * FROM students WHERE name LIKE %s"
        cursor = self.connection.cursor(dictionary=True)
        cursor.execute(query, (f"%{name}%",))
        result = cursor.fetchall()
        cursor.close()
        return [Student.from_dict(student) for student in result]

    def create(self, student: Dict[str, Any]) -> Optional[Student]:
        """
        Create a new student
        :param student: Dictionary with student data
        :return: Created Student object or None if failed
        """
        query = "INSERT INTO students (name, email) VALUES (%s, %s)"
        cursor = self.connection.cursor()
        cursor.execute(query, (student["name"], student["email"]))
        self.connection.commit()
        student_id = cursor.lastrowid
        cursor.close()
        return self.get_by_id(student_id)

    def update(self, student_id: int, student: Dict[str, Any]) -> Optional[Student]:
        """
        Update a student
        :param student_id: id of the student to update
        :param student: Dictionary with student data
        :return: Updated Student object or None if failed
        """
        query = "UPDATE students SET name = %s, email = %s WHERE id = %s"
        cursor = self.connection.cursor()
        cursor.execute(query, (student["name"], student["email"], student_id))
        self.connection.commit()
        cursor.close()
        return self.get_by_id(student_id)

    def delete(self, student_id: int) -> bool:
        """
        Delete a student
        :param student_id: id of the student to delete
        :return: True if deleted, False if not
        """
        query = "DELETE FROM students WHERE id = %s"
        cursor = self.connection.cursor()
        cursor.execute(query, (student_id,))
        self.connection.commit()
        deleted = cursor.rowcount > 0
        cursor.close()
        return deleted
